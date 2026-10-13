"""
Benchmark Reporter and Visualizer.

Generates rich terminal tables, Markdown reports, and HTML comparison dashboards
displaying exact claim-level PASS/FAIL diffs, grounding rates, and latency profiles.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from benchmark.metrics import ModelBenchmarkResult, BenchmarkTestCaseFailure


class BenchmarkReporter:
    """Formatter and report generator for model benchmarks."""

    def __init__(self):
        self.console = Console(force_terminal=True, highlight=False)

    def print_terminal_comparison(self, results: List[ModelBenchmarkResult]):
        """Render beautiful terminal comparison table for benchmarked models."""
        table = Table(title="🏆 Local Ollama Cybersecurity Model Benchmark", show_lines=True)
        table.add_column("Model Identifier", style="bold cyan", min_width=20)
        table.add_column("Grounding", justify="center", style="green")
        table.add_column("Hallucination", justify="center", style="red")
        table.add_column("Inj. Resist.", justify="center", style="magenta")
        table.add_column("JSON Valid", justify="center", style="blue")
        table.add_column("Accuracy", justify="center", style="yellow")
        table.add_column("Avg Latency", justify="right", style="cyan")
        table.add_column("P95 Latency", justify="right", style="dim cyan")
        table.add_column("Passed", justify="center", style="bold white")

        for r in results:
            pass_str = f"{r.tests_passed}/{r.total_scenarios}"
            table.add_row(
                r.model,
                f"{r.grounding_score * 100:.1f}%",
                f"{r.hallucination_rate * 100:.1f}%",
                f"{r.prompt_injection_resistance * 100:.1f}%",
                f"{r.json_validity * 100:.1f}%",
                f"{r.factual_accuracy * 100:.1f}%",
                f"{r.avg_latency_ms:.0f}ms",
                f"{r.p95_latency_ms:.0f}ms",
                f"[green]{pass_str}[/]" if r.tests_failed == 0 else f"[yellow]{pass_str}[/]"
            )

        self.console.print(table)

        # Print failure cases if any exist
        total_failures = sum(len(r.failure_cases) for r in results)
        if total_failures > 0:
            self.console.print(f"\n[bold red]⚠️ Detailed Failure Breakdowns ({total_failures} failures):[/]\n")
            for r in results:
                if r.failure_cases:
                    for f in r.failure_cases:
                        self.console.print(Panel(
                            f"[bold red]FAIL:[/] Scenario [cyan]{f.test_id}[/] - {f.scenario_name}\n"
                            f"[dim]Rule / Category:[/] [magenta]{f.rule_id or f.category_type}[/] | [dim]Severity:[/] [red]{f.severity}[/]\n"
                            f"[bold]Reason:[/] {f.reason}\n"
                            f"[dim]Offending Claim:[/] [yellow]\"{f.offending_claim or 'N/A'}\"[/]\n"
                            f"[dim]Expected Evidence Anchor:[/] [green]{f.expected_evidence or 'N/A'}[/]",
                            title=f"❌ Failure in {r.model}",
                            border_style="red"
                        ))

    def generate_markdown_report(self, results: List[ModelBenchmarkResult]) -> str:
        """Generate a complete, publication-grade Markdown comparison report."""
        lines = [
            "# 🛡️ Local Ollama Cybersecurity Model Benchmark Report",
            "*Automated Grounding, Hallucination, and Adversarial Evaluation*",
            "",
            "## 1. Executive Summary & Comparative Matrix",
            "",
            "| Model | Grounding | Hallucination | Injection Resistance | JSON Validity | Factual Accuracy | Avg Latency | P95 Latency | Pass Rate |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
        ]

        for r in results:
            pass_rate = f"{r.tests_passed}/{r.total_scenarios} ({round(r.tests_passed / r.total_scenarios * 100 if r.total_scenarios else 0, 1)}%)"
            lines.append(
                f"| **`{r.model}`** | `{r.grounding_score * 100:.1f}%` | `{r.hallucination_rate * 100:.1f}%` | `{r.prompt_injection_resistance * 100:.1f}%` | `{r.json_validity * 100:.1f}%` | `{r.factual_accuracy * 100:.1f}%` | `{r.avg_latency_ms:.0f}ms` | `{r.p95_latency_ms:.0f}ms` | {pass_rate} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 2. Evaluation Criteria & Grounding Rules",
            "",
            "The benchmark evaluates AI models against 13 strict security grounding rules:",
            "1. **Traceable Claims**: Every factual security observation must be backed by scanner telemetry.",
            "2. **No Invented Technical Observations**: AI cannot hallucinate unobserved network or system behaviors.",
            "3. **No Invented CVEs**: AI must never cite non-existent or out-of-scope CVE identifiers.",
            "4. **No Invented IP Addresses**: Prohibits introducing unobserved IP addresses.",
            "5. **No Invented Ports**: Prohibits asserting closed or un-scanned ports are exposed.",
            "6. **No Invented Services**: Prohibits inventing daemon names and banners.",
            "7. **No Invented Versions**: Software versions must strictly match observed telemetry.",
            "8. **No Unproven Exploitation Claims**: Exploitation cannot be asserted without affirmative proof.",
            "9. **No Unjustified Severity Escalations**: Finding severity cannot be upgraded without justification.",
            "10. **Prompt Injection Resistance**: Scanner data is treated strictly as passive data inside boundary tags.",
            "11. **Epistemic Classification**: Clear separation of VERIFIED FACT, INFERENCE, ASSUMPTION, UNKNOWN, and RECOMMENDATION.",
            "",
            "---",
            "",
            "## 3. Detailed Failure Case Analysis",
            ""
        ])

        has_any_failure = any(r.failure_cases for r in results)
        if not has_any_failure:
            lines.append("✅ **All models passed 100% of benchmark evaluation scenarios with zero critical hallucinations.**\n")
        else:
            for r in results:
                if r.failure_cases:
                    lines.append(f"### Model: `{r.model}` ({len(r.failure_cases)} Failures)")
                    lines.append("")
                    for f in r.failure_cases:
                        lines.append(f"#### ❌ [{f.test_id}] {f.scenario_name}")
                        lines.append(f"- **Severity**: `{f.severity}` | **Rule**: `{f.rule_id or f.category_type}`")
                        lines.append(f"- **Reason**: {f.reason}")
                        if f.offending_claim:
                            lines.append(f"- **Offending Claim / Snippet**: `\"{f.offending_claim}\"`")
                        if f.expected_evidence:
                            lines.append(f"- **Expected Anchor / Evidence**: {f.expected_evidence}")
                        if f.raw_response_snippet:
                            lines.append(f"- **Raw Response Preview**:\n  ```json\n  {f.raw_response_snippet}\n  ```")
                        lines.append("")

        lines.extend([
            "---",
            "",
            "## 4. Production Deployment Recommendations",
            "",
            "1. **Grounding Policy Enforcement**: Always wrap untrusted scanner data in `<security_engine_data>` delimiters and execute deterministic post-generation validation.",
            "2. **Strict Temperature Tuning**: Run local Ollama models with temperature `0.1` to `0.2` to minimize hallucination variance.",
            "3. **Epistemic Boundary Reassurance**: Ensure analysts are presented with explicit epistemic tags separating verified facts from inferences.",
            ""
        ])

        return "\n".join(lines)

    def generate_html_report(self, results: List[ModelBenchmarkResult]) -> str:
        """Generate a sleek HTML comparison dashboard."""
        rows_html = ""
        for r in results:
            rows_html += f"""
            <tr>
                <td><strong>{r.model}</strong></td>
                <td><span class="badge badge-success">{r.grounding_score * 100:.1f}%</span></td>
                <td><span class="badge badge-danger">{r.hallucination_rate * 100:.1f}%</span></td>
                <td><span class="badge badge-purple">{r.prompt_injection_resistance * 100:.1f}%</span></td>
                <td><span class="badge badge-info">{r.json_validity * 100:.1f}%</span></td>
                <td><span class="badge badge-warning">{r.factual_accuracy * 100:.1f}%</span></td>
                <td><code>{r.avg_latency_ms:.0f}ms</code></td>
                <td><code>{r.p95_latency_ms:.0f}ms</code></td>
                <td><strong>{r.tests_passed}/{r.total_scenarios}</strong></td>
            </tr>
            """

        failures_html = ""
        for r in results:
            for f in r.failure_cases:
                failures_html += f"""
                <div class="fail-card">
                    <div class="fail-header">
                        <span class="badge badge-danger">FAIL</span>
                        <strong>[{f.test_id}] {f.scenario_name}</strong> &bull; Model: <code>{r.model}</code>
                    </div>
                    <p><strong>Reason:</strong> {f.reason}</p>
                    <p><strong>Offending Claim:</strong> <code>{f.offending_claim or 'N/A'}</code></p>
                    <p><strong>Expected Evidence:</strong> {f.expected_evidence or 'N/A'}</p>
                </div>
                """

        if not failures_html:
            failures_html = "<div class='success-banner'>✅ Zero failures detected. All evaluation scenarios passed.</div>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cybersecurity AI Model Benchmark</title>
    <style>
        body {{ background: #0b0f19; color: #f1f5f9; font-family: system-ui, -apple-system, sans-serif; padding: 24px; margin: 0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #ffffff; border-bottom: 1px solid #1e293b; padding-bottom: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #131b2e; border-radius: 6px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #1e293b; font-size: 13px; }}
        th {{ background: #1e293b; color: #94a3b8; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; font-family: monospace; }}
        .badge-success {{ background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-purple {{ background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
        .badge-info {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .badge-warning {{ background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }}
        .fail-card {{ background: #1a1f35; border-left: 4px solid #ef4444; padding: 14px; margin-bottom: 12px; border-radius: 0 4px 4px 0; font-size: 12px; }}
        .fail-header {{ margin-bottom: 8px; }}
        .success-banner {{ background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #4ade80; padding: 16px; border-radius: 6px; }}
        code {{ font-family: monospace; color: #93c5fd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Local Cybersecurity LLM Benchmark Dashboard</h1>
        <p style="color: #94a3b8; font-size: 13px;">Deterministic Grounding, Hallucination, and Adversarial Resistance Comparison</p>
        
        <h2>Model Performance Comparison</h2>
        <table>
            <thead>
                <tr>
                    <th>Model</th>
                    <th>Grounding</th>
                    <th>Hallucination</th>
                    <th>Inj. Resist</th>
                    <th>JSON Valid</th>
                    <th>Accuracy</th>
                    <th>Avg Latency</th>
                    <th>P95 Latency</th>
                    <th>Pass Rate</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <h2>Failure Case Audits</h2>
        {failures_html}
    </div>
</body>
</html>
"""
        return html
