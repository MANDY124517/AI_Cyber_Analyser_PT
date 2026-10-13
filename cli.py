import sys
import os
import json
import asyncio
import argparse

# Force UTF-8 encoding on standard output for Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from models import SecurityFinding
from pipeline.runner import FindingsPipelineRunner
from pipeline.ai_engine import clean_and_parse_json
from schema.normalizer import SecurityEngineNormalizer
from grounding.evaluator import GroundingEvaluator
from benchmark.runner import BenchmarkRunner
from benchmark.reporter import BenchmarkReporter

console = Console(force_terminal=True, highlight=False)

def get_severity_style(sev: str) -> str:
    s = sev.upper()
    if s == "CRITICAL":
        return "bold red"
    elif s == "HIGH":
        return "bold orange3"
    elif s == "MEDIUM":
        return "bold yellow"
    return "bold blue"

def cmd_list(args):
    """List all findings in the dataset."""
    runner = FindingsPipelineRunner(data_path=args.data)
    findings = runner.load_findings()

    table = Table(title="🛡️ Cybersecurity Ingested Findings", show_lines=True)
    table.add_column("ID", style="bold cyan", width=10)
    table.add_column("Title", style="white", min_width=30)
    table.add_column("Category", style="magenta", width=18)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("CVE / Ref", style="dim", width=16)
    table.add_column("Asset / Target", style="green", width=25)

    for f in findings:
        table.add_row(
            f.id,
            f.title,
            f.category,
            f"[{get_severity_style(f.severity)}]{f.severity}[/]",
            f.cve_id or "-",
            f.asset
        )

    console.print(table)
    console.print(f"\n[bold green]Total findings loaded:[/] {len(findings)}\n")

async def cmd_analyze(args):
    """Analyze a single finding by ID."""
    runner = FindingsPipelineRunner(data_path=args.data, provider=args.provider)
    findings = runner.load_findings()
    
    target = next((f for f in findings if f.id.upper() == args.id.upper()), None)
    if not target:
        console.print(f"[bold red]Error:[/] Finding ID '{args.id}' not found in dataset.")
        sys.exit(1)

    with console.status(f"[bold cyan]Running AI Security Analysis on {target.id}...[/]"):
        if getattr(args, "grounded", False):
            grounded_res = await runner.analyze_grounded(target)
            f = target
            a = grounded_res.analysis
            eval_res = grounded_res.evaluation
        else:
            enriched = await runner.analyze_single(target)
            f = enriched.finding
            a = enriched.analysis
            eval_res = None

    # Render summary header
    console.print(Panel(
        f"[bold white]{f.title}[/]\n"
        f"[dim]ID:[/] [cyan]{f.id}[/] | [dim]Severity:[/] [{get_severity_style(f.severity)}]{f.severity}[/] | [dim]Category:[/] [magenta]{f.category}[/] | [dim]Asset:[/] [green]{f.asset}[/]",
        title="🔍 Finding Metadata",
        border_style="cyan"
    ))

    if not a:
        console.print("[red]Analysis failed to generate.[/]")
        return

    # 1. Executive Summary Panel
    console.print(Panel(
        f"[bold italic yellow]{a.executive_summary}[/]\n\n"
        f"[bold]Suggested Priority:[/] [red]{a.suggested_priority}[/]  |  [bold]Remediation Effort:[/] [cyan]{a.remediation_effort}[/]  |  [bold]Confidence:[/] [green]{a.confidence_score * 100:.0f}% ({a.confidence_rating})[/]\n"
        f"[dim]Confidence Justification:[/] {a.confidence_reasoning}",
        title="👔 Executive & CISO Overview",
        border_style="yellow"
    ))

    # 2. Technical & Evidence Panel
    console.print(Panel(
        f"[bold cyan]Explanation:[/] {a.explanation}\n\n"
        f"[bold red]Technical Impact:[/] {a.impact.technical_impact}\n"
        f"[bold orange3]Business Impact:[/] {a.impact.business_impact}\n"
        f"[bold magenta]Blast Radius:[/] {a.impact.blast_radius}\n\n"
        f"[bold green]Evidence Interpretation:[/] {a.evidence_interpretation}",
        title="🔬 Technical Deep-Dive & Impact",
        border_style="blue"
    ))

    # 3. Developer Guidance & Remediation
    rem = a.recommended_remediation
    dev_content = (
        f"[bold cyan]Developer Context:[/] {a.developer_oriented_explanation}\n\n"
        f"[bold red]Immediate Containment:[/] {rem.immediate_mitigation}\n"
        f"[bold green]Permanent Resolution:[/] {rem.permanent_fix}\n\n"
        f"[bold yellow]Verification Steps:[/] {rem.verification_steps}"
    )
    console.print(Panel(dev_content, title="💻 Developer Remediation Roadmap", border_style="green"))

    if rem.code_sample_patch:
        syntax = Syntax(rem.code_sample_patch, "diff", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title="🛠️ Code Sample / Config Patch", border_style="dim green"))

    if eval_res:
        eval_color = "green" if eval_res.evaluation_passed else "red"
        eval_text = (
            f"[bold]Grounding Score:[/] [{eval_color}]{eval_res.grounding_score * 100:.1f}%[/]  |  "
            f"[bold]Hallucination Score:[/] [yellow]{eval_res.hallucination_score * 100:.1f}%[/]  |  "
            f"[bold]Prompt Injection Resistance:[/] [cyan]{'COMPROMISED' if eval_res.prompt_injection_detected else 'SECURE'}[/]\n\n"
            f"[bold green]Grounded Claims Verified:[/] {len(eval_res.supported_claims)}\n"
            f"[bold red]Unsupported Claims Detected:[/] {len(eval_res.unsupported_claims)}"
        )
        if eval_res.guardian_audit:
            g = eval_res.guardian_audit
            g_status = "[bold green]PASS[/]" if g.is_safe else "[bold red]FAIL[/]"
            eval_text += f"\n\n[bold magenta]IBM Granite Guardian 3 (8B) Audit:[/] {g_status} ({g.guardian_latency_ms}ms)\n"
            eval_text += f"- Groundedness: {'SAFE' if g.groundedness_passed else '[bold red]VIOLATION[/]'}\n"
            eval_text += f"- Jailbreak / Injection: {'SAFE' if not g.jailbreak_detected else '[bold red]DETECTED[/]'}\n"
            if g.audit_notes:
                eval_text += f"- Notes: {g.audit_notes}"

        if eval_res.security_policy_violations:
            eval_text += "\n\n[bold red]Policy Violations:[/]\n" + "\n".join(f"- {v}" for v in eval_res.security_policy_violations)
        console.print(Panel(eval_text, title="🛡️ Deterministic Security Grounding Audit", border_style=eval_color))

async def cmd_evaluate(args):
    """Run deterministic grounding evaluation on a finding."""
    runner = FindingsPipelineRunner(data_path=args.data, provider=args.provider)
    findings = runner.load_findings()
    
    target = next((f for f in findings if f.id.upper() == args.id.upper()), None)
    if not target:
        console.print(f"[bold red]Error:[/] Finding ID '{args.id}' not found in dataset.")
        sys.exit(1)

    with console.status(f"[bold cyan]Evaluating Grounding on {target.id}...[/]"):
        grounded_res = await runner.analyze_grounded(
            target,
            target_model=getattr(args, "model", None),
            enable_guardian=getattr(args, "guardian", False)
        )

    evaluator = GroundingEvaluator()
    eval_diff = evaluator.format_evaluation_diff(grounded_res.evaluation, target.id) # type: ignore
    console.print(Panel(eval_diff, title=f"Audit Results for {target.id}", border_style="cyan"))

async def cmd_guardian(args):
    """Run IBM Granite Guardian 3 safety, grounding, and injection audit."""
    from grounding.guardian import GraniteGuardianVerifier
    runner = FindingsPipelineRunner(data_path=args.data)
    findings = runner.load_findings()

    target = next((f for f in findings if f.id.upper() == args.id.upper()), None)
    if not target:
        console.print(f"[bold red]Error:[/] Finding ID '{args.id}' not found in dataset.")
        sys.exit(1)

    verifier = GraniteGuardianVerifier(guardian_model=args.model)
    with console.status(f"[bold cyan]Running IBM Granite Guardian 3 Audit on {target.id}...[/]"):
        context_text = f"Asset: {target.asset}. CVE: {target.cve_id or 'None'}. Severity: {target.severity}. Evidence: {json.dumps(target.evidence)}"
        # Run standard analysis first
        enriched = await runner.analyze_single(target)
        analysis_text = f"{enriched.analysis.explanation} {enriched.analysis.recommended_remediation.permanent_fix}"
        
        audit_res = await verifier.audit_finding(
            context_text=context_text,
            ai_response_text=analysis_text,
            raw_telemetry=json.dumps(target.evidence)
        )

    status_badge = "[bold green]PASSED[/]" if audit_res.is_safe else "[bold red]FLAGGED RISK[/]"
    content = (
        f"[bold]Target Finding:[/] [cyan]{target.id}[/] ({target.title})\n"
        f"[bold]Guardian Model:[/] [yellow]{audit_res.guardian_model}[/]\n"
        f"[bold]Overall Verdict:[/] {status_badge}  |  [dim]Latency:[/] {audit_res.guardian_latency_ms}ms\n\n"
        f"[bold]Groundedness Check:[/] {'[bold green]GROUNDED[/]' if audit_res.groundedness_passed else '[bold red]UNGROUNDED / HALLUCINATED[/]'}\n"
        f"[bold]Jailbreak / Injection:[/] {'[bold green]CLEAN[/]' if not audit_res.jailbreak_detected else '[bold red]PROMPT INJECTION DETECTED[/]'}\n"
        f"[bold]Raw Output:[/] {audit_res.raw_verdict}\n"
        f"[bold]Audit Notes:[/] {audit_res.audit_notes}"
    )
    console.print(Panel(content, title="🛡️ IBM Granite Guardian 3 Verification Report", border_style="magenta"))

async def cmd_benchmark(args):
    """Execute model benchmarking suite."""
    runner = BenchmarkRunner(ollama_host=args.host)
    reporter = BenchmarkReporter()

    target_models = []
    discovered = runner.discover_ollama_models()
    if args.all:
        if discovered:
            target_models.extend(discovered)
        else:
            default_model = os.getenv("OLLAMA_MODEL", "hermes3:3b")
            target_models = [default_model]
    elif args.model:
        target_models = [args.model]
    else:
        default_model = os.getenv("OLLAMA_MODEL", "hermes3:3b")
        target_models = discovered if discovered else [default_model]

    console.print(f"[bold cyan]🚀 Starting Cybersecurity AI Benchmark[/] on models: [yellow]{target_models}[/]\n")
    results = []
    for model in target_models:
        with console.status(f"[bold cyan]Benchmarking {model}...[/]"):
            result = await runner.run_benchmark_for_model(model=model, suite_name=args.suite)
            results.append(result)

    reporter.print_terminal_comparison(results)

async def cmd_batch(args):
    """Run batch analysis over all findings and generate reports."""
    runner = FindingsPipelineRunner(data_path=args.data, provider=args.provider)
    findings = runner.load_findings()

    console.print(f"[bold cyan]Starting batch AI processing for {len(findings)} findings...[/]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("Analyzing security findings...", total=len(findings))
        
        enriched_list = []
        for f in findings:
            progress.update(task, description=f"Processing {f.id} - {f.title[:25]}...")
            enriched = await runner.analyze_single(f)
            enriched_list.append(enriched)
            progress.advance(task)

    report = runner.compile_report(enriched_list)
    m = report.metrics

    console.print("\n[bold green]✅ Batch AI Analysis Completed Successfully![/]\n")
    
    metrics_table = Table(title="📊 Security Posture & AI Metrics Summary", show_lines=True)
    metrics_table.add_column("Metric", style="cyan")
    metrics_table.add_column("Value", style="bold white")
    metrics_table.add_row("Total Ingested Findings", str(m.total_findings))
    metrics_table.add_row("Analyzed Findings", f"{m.analyzed_findings} / {m.total_findings}")
    metrics_table.add_row("Critical / High Severity Findings", f"[bold red]{m.critical_or_high_count}[/]")
    metrics_table.add_row("Average AI Confidence", f"[bold green]{m.average_confidence * 100:.1f}%[/]")
    console.print(metrics_table)

    # Export
    out_format = args.format.lower()
    out_path = args.output

    if out_format == "json":
        path = runner.export_json(report, out_path or "security_ai_report.json")
        console.print(f"[bold green]Structured JSON report exported to:[/] [cyan]{path}[/]")
    elif out_format == "markdown":
        path = out_path or "security_ai_report.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(runner.export_markdown(report))
        console.print(f"[bold green]Markdown report exported to:[/] [cyan]{path}[/]")
    elif out_format == "html":
        path = out_path or "security_ai_report.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(runner.export_html(report))
        console.print(f"[bold green]HTML dashboard report exported to:[/] [cyan]{path}[/]")

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity AI Findings Analysis & Benchmark CLI")
    parser.add_argument("--data", default="data/findings.json", help="Path to findings dataset JSON")
    parser.add_argument("--provider", default=None, help="LLM Provider (gemini, openai, anthropic, ollama)")
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = subparsers.add_parser("list", help="List all security findings")
    p_list.set_defaults(func=cmd_list)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze single finding by ID")
    p_analyze.add_argument("--id", required=True, help="Finding ID (e.g. SEC-001)")
    p_analyze.add_argument("--model", default=None, help="Target Ollama model (e.g. qwen2.5:7b, hermes3:3b)")
    p_analyze.add_argument("--grounded", action="store_true", help="Include deterministic grounding evaluation")
    p_analyze.add_argument("--guardian", action="store_true", help="Enable IBM Granite Guardian 3 verification")
    p_analyze.set_defaults(func=lambda args: asyncio.run(cmd_analyze(args)))

    # evaluate
    p_eval = subparsers.add_parser("evaluate", help="Perform deterministic grounding evaluation on finding")
    p_eval.add_argument("--id", required=True, help="Finding ID (e.g. SEC-001)")
    p_eval.add_argument("--model", default=None, help="Target Ollama model")
    p_eval.add_argument("--guardian", action="store_true", help="Include Granite Guardian verification")
    p_eval.set_defaults(func=lambda args: asyncio.run(cmd_evaluate(args)))

    # guardian
    p_guard = subparsers.add_parser("guardian", help="Audit finding directly with IBM Granite Guardian 3 (8B)")
    p_guard.add_argument("--id", required=True, help="Finding ID (e.g. SEC-001)")
    p_guard.add_argument("--model", default="ibm/granite3-guardian:8b", help="Granite Guardian model name")
    p_guard.set_defaults(func=lambda args: asyncio.run(cmd_guardian(args)))

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Benchmark Ollama models against hallucination & adversarial datasets")
    p_bench.add_argument("--model", help="Specific model name (e.g. qwen2.5:7b, ibm/granite3-guardian:8b)")
    p_bench.add_argument("--all", action="store_true", help="Benchmark all discovered models")
    p_bench.add_argument("--suite", default="all", choices=["all", "hallucination", "adversarial"], help="Suite to run")
    p_bench.add_argument("--host", default=None, help="Ollama host")
    p_bench.set_defaults(func=lambda args: asyncio.run(cmd_benchmark(args)))

    # batch
    p_batch = subparsers.add_parser("batch", help="Batch analyze all findings and export report")
    p_batch.add_argument("--output", default=None, help="Output file path")
    p_batch.add_argument("--format", default="json", choices=["json", "markdown", "html"], help="Export format")
    p_batch.set_defaults(func=lambda args: asyncio.run(cmd_batch(args)))

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
