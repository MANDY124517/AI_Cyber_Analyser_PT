"""
Integration Tests for Hallucination and Adversarial Test Suites.
"""

import pytest
import os
import json
import asyncio

from models import SecurityFinding, FindingAnalysis, ImpactAnalysis, RemediationPlan
from schema.normalizer import SecurityEngineNormalizer
from grounding.evaluator import GroundingEvaluator
from benchmark.runner import BenchmarkRunner
from benchmark.metrics import ModelBenchmarkResult


def test_hallucination_dataset_integrity():
    """Verify all 15 scenarios in hallucination suite are syntactically valid and well-formed."""
    runner = BenchmarkRunner()
    scenarios = runner.load_suite("hallucination")
    assert len(scenarios) >= 15

    for sc in scenarios:
        assert "id" in sc
        assert "scenario_name" in sc
        assert "category_type" in sc
        assert "context" in sc
        assert "grounding_expectation" in sc


def test_adversarial_dataset_integrity():
    """Verify all adversarial scenarios are well-formed."""
    runner = BenchmarkRunner()
    scenarios = runner.load_suite("adversarial")
    assert len(scenarios) >= 5

    for sc in scenarios:
        assert "id" in sc
        assert "attack_type" in sc
        assert "context" in sc
        assert "expectation" in sc


def test_evaluator_against_hallucination_suite_grounding():
    """Verify that GroundingEvaluator deterministically verifies grounding across hallucination scenarios."""
    evaluator = GroundingEvaluator()
    runner = BenchmarkRunner()
    scenarios = runner.load_suite("hallucination")

    # Test valid grounded analysis against scenario 1
    sc0 = scenarios[0]
    finding = SecurityFinding.model_validate(sc0["context"])
    context = SecurityEngineNormalizer.from_security_finding(finding)

    valid_analysis = FindingAnalysis(
        explanation="Detected OpenSSH Remote Code Execution CVE-2024-6387 on port 22.",
        impact=ImpactAnalysis(
            technical_impact="Remote code execution on bastion.",
            business_impact="Compliance violation.",
            blast_radius="Bastion node."
        ),
        evidence_interpretation="Trivy verified OpenSSH 9.2p1 on port 22.",
        recommended_remediation=RemediationPlan(
            immediate_mitigation="Restrict port 22 access.",
            permanent_fix="Update OpenSSH to patched version.",
            verification_steps="Re-scan with Trivy."
        ),
        executive_summary="High severity OpenSSH vulnerability detected.",
        developer_oriented_explanation="Update package version.",
        confidence_reasoning="Scanner verified banner.",
        confidence_score=0.95,
        confidence_rating="HIGH",
        remediation_effort="Low",
        suggested_priority="P1 - High"
    )
    res = evaluator.evaluate_response(valid_analysis, context)
    assert res.evaluation_passed is True
    assert res.grounding_score >= 0.90
