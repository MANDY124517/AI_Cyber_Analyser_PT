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

    table = Table(title="🛡️ Cybersecurity Mock Findings Dataset", show_lines=True)
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
        enriched = await runner.analyze_single(target)

    f = enriched.finding
    a = enriched.analysis

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
    parser = argparse.ArgumentParser(description="Cybersecurity AI Findings Analysis CLI")
    parser.add_argument("--data", default="data/findings.json", help="Path to findings dataset JSON")
    parser.add_argument("--provider", default=None, help="LLM Provider (gemini, openai, anthropic, ollama, expert-engine)")
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = subparsers.add_parser("list", help="List all security findings")
    p_list.set_defaults(func=cmd_list)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze single finding by ID")
    p_analyze.add_argument("--id", required=True, help="Finding ID (e.g. SEC-001)")
    p_analyze.set_defaults(func=lambda args: asyncio.run(cmd_analyze(args)))

    # batch
    p_batch = subparsers.add_parser("batch", help="Batch analyze all findings and export report")
    p_batch.add_argument("--output", default=None, help="Output file path")
    p_batch.add_argument("--format", default="json", choices=["json", "markdown", "html"], help="Export format")
    p_batch.set_defaults(func=lambda args: asyncio.run(cmd_batch(args)))

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
