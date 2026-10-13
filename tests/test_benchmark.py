"""
Unit & Integration Tests for Model Benchmarking, Metric Aggregation, and Reporting.
"""

import pytest
import asyncio
from benchmark.runner import BenchmarkRunner
from benchmark.reporter import BenchmarkReporter
from benchmark.metrics import (
    ModelBenchmarkResult,
    BenchmarkTestCaseFailure,
    calculate_percentile,
)


def test_percentile_calculation():
    """Verify percentile calculation math."""
    data = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    p95 = calculate_percentile(data, 95.0)
    assert 90.0 <= p95 <= 100.0

    assert calculate_percentile([], 95.0) == 0.0
    assert calculate_percentile([42.0], 95.0) == 42.0


def test_benchmark_reporter_markdown_and_html():
    """Verify Markdown and HTML report generation from benchmark results."""
    reporter = BenchmarkReporter()

    sample_result = ModelBenchmarkResult(
        model="hermes3:3b",
        benchmark_version="1.0",
        suite_name="all",
        total_scenarios=20,
        tests_passed=19,
        tests_failed=1,
        grounding_score=0.95,
        hallucination_rate=0.05,
        unsupported_claim_rate=0.05,
        prompt_injection_resistance=0.98,
        factual_accuracy=0.95,
        json_validity=1.0,
        avg_latency_ms=1250.0,
        p95_latency_ms=2100.0,
        failure_cases=[
            BenchmarkTestCaseFailure(
                test_id="HALLUC-05-EMPTY-RESULTS",
                scenario_name="Empty Scan",
                category_type="empty_data",
                rule_id="RULE-05-PORT",
                reason="Claimed port 443 was exposed",
                offending_claim="Port 443 exposed",
                expected_evidence="No open ports in evidence",
                severity="HIGH"
            )
        ]
    )

    md = reporter.generate_markdown_report([sample_result])
    assert "# 🛡️ Local Ollama Cybersecurity Model Benchmark Report" in md
    assert "hermes3:3b" in md
    assert "HALLUC-05-EMPTY-RESULTS" in md

    html = reporter.generate_html_report([sample_result])
    assert "<!DOCTYPE html>" in html
    assert "hermes3:3b" in html
    assert "HALLUC-05-EMPTY-RESULTS" in html


def test_benchmark_runner_suite_loading():
    """Verify that benchmark runner loads scenarios properly."""
    runner = BenchmarkRunner()
    scenarios = runner.load_suite("all")
    assert len(scenarios) >= 20
