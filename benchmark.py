#!/usr/bin/env python3
"""
Top-Level CLI for Cybersecurity AI Model Benchmarking & Grounding Evaluation.

Usage:
  python benchmark.py --model hermes3:3b
  python benchmark.py --all
  python benchmark.py --suite hallucination
  python benchmark.py --suite adversarial
  python benchmark.py --format markdown --output benchmark_report.md
"""

import sys
import os
import asyncio
import argparse

# Force UTF-8 on Windows standard output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.runner import BenchmarkRunner
from benchmark.reporter import BenchmarkReporter


async def main_async(args):
    runner = BenchmarkRunner(ollama_host=args.host)
    reporter = BenchmarkReporter()

    # Discover or select models
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
        if default_model in discovered:
            target_models = [default_model]
        elif discovered:
            target_models = [discovered[0]]
        else:
            target_models = [default_model]

    reporter.console.print(f"[bold cyan]🚀 Starting Cybersecurity AI Benchmark[/] on models: [yellow]{target_models}[/]")
    reporter.console.print(f"[dim]Suite:[/] [magenta]{args.suite}[/] | [dim]Ollama Host:[/] [green]{runner.ollama_host}[/]\n")

    results = []
    for model in target_models:
        with reporter.console.status(f"[bold cyan]Running benchmark suite '{args.suite}' on {model}...[/]"):
            result = await runner.run_benchmark_for_model(
                model=model,
                suite_name=args.suite,
                max_concurrency=args.concurrency
            )
            results.append(result)

    # Output results
    reporter.print_terminal_comparison(results)

    # Export
    out_format = args.format.lower()
    if out_format == "markdown":
        md_content = reporter.generate_markdown_report(results)
        out_path = args.output or "benchmark_report.md"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        reporter.console.print(f"\n[bold green]✅ Markdown benchmark report exported to:[/] [cyan]{out_path}[/]\n")
    elif out_format == "html":
        html_content = reporter.generate_html_report(results)
        out_path = args.output or "benchmark_report.html"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        reporter.console.print(f"\n[bold green]✅ HTML dashboard benchmark report exported to:[/] [cyan]{out_path}[/]\n")
    elif out_format == "json":
        import json
        out_path = args.output or "benchmark_results.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([r.model_dump(mode="json") for r in results], f, indent=2)
        reporter.console.print(f"\n[bold green]✅ JSON benchmark results exported to:[/] [cyan]{out_path}[/]\n")


def main():
    parser = argparse.ArgumentParser(description="Cybersecurity AI Grounding & Model Benchmark CLI")
    parser.add_argument("--model", help="Specific model name to evaluate (e.g. qwen2.5:7b, ibm/granite3-guardian:8b, hermes3:3b)")
    parser.add_argument("--all", action="store_true", help="Benchmark all discovered local Ollama models")
    parser.add_argument("--suite", default="all", choices=["all", "hallucination", "adversarial"], help="Benchmark test suite")
    parser.add_argument("--host", default=None, help="Ollama host URL (default: http://127.0.0.1:11434)")
    parser.add_argument("--concurrency", type=int, default=1, help="Max concurrency for local model evaluation")
    parser.add_argument("--format", default="markdown", choices=["terminal", "markdown", "html", "json"], help="Export format")
    parser.add_argument("--output", default=None, help="Output file path for reports")

    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
