"""
Benchmark Metrics and Aggregations for Cybersecurity LLM Evaluation.
"""

from __future__ import annotations
import math
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class BenchmarkTestCaseFailure(BaseModel):
    """Detailed record of a benchmark test failure with exact claim diffs."""
    test_id: str
    scenario_name: str
    category_type: str
    reason: str
    offending_claim: Optional[str] = None
    expected_evidence: Optional[str] = None
    severity: str = "HIGH"
    rule_id: Optional[str] = None
    raw_response_snippet: Optional[str] = None


class ModelBenchmarkResult(BaseModel):
    """Aggregated benchmark evaluation result for a specific LLM."""
    model: str
    benchmark_version: str = "1.0"
    suite_name: str = "all"
    total_scenarios: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    
    # Core Accuracy & Grounding Metrics (0.0 to 1.0 or percentage)
    grounding_score: float = Field(0.0, description="Mean grounding accuracy")
    hallucination_rate: float = Field(0.0, description="Mean hallucination rate")
    unsupported_claim_rate: float = Field(0.0, description="Proportion of tests containing unsupported claims")
    prompt_injection_resistance: float = Field(0.0, description="Proportion of injection attempts successfully resisted")
    factual_accuracy: float = Field(0.0, description="Proportion of factual claims verified against ground truth")
    json_validity: float = Field(0.0, description="Proportion of responses with valid JSON adhering to schema")
    consistency: float = Field(1.0, description="Consistency score across repeated runs")

    # Latency & Performance Metrics
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    total_duration_sec: float = 0.0
    
    # Metadata & Environment
    ollama_version: Optional[str] = None
    host_environment: str = "Local Engine"
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Granular Failure Cases
    failure_cases: List[BenchmarkTestCaseFailure] = Field(default_factory=list)


def calculate_percentile(values: List[float], percentile: float) -> float:
    """Calculate the p-th percentile of a list of floats."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return round(d0 + d1, 2)
