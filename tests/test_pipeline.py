import pytest
import json
import os
import asyncio
from fastapi.testclient import TestClient

from models import SecurityFinding, FindingAnalysis, BatchReport
from pipeline.runner import FindingsPipelineRunner
from pipeline.ai_engine import CybersecurityAIEngine
from api.server import app

client = TestClient(app)

def test_dataset_loading():
    """Verify that all mock findings load and match the Pydantic schema."""
    runner = FindingsPipelineRunner("data/findings.json")
    findings = runner.load_findings()
    assert len(findings) >= 15
    for f in findings:
        assert isinstance(f, SecurityFinding)
        assert f.id.startswith("SEC-")
        assert f.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        assert len(f.evidence) > 0

def test_dataset_diversity():
    """Verify that the dataset includes all required cybersecurity vulnerability classes."""
    runner = FindingsPipelineRunner("data/findings.json")
    findings = runner.load_findings()
    categories = {f.category for f in findings}
    
    assert "CVE" in categories
    assert "XSS" in categories
    assert "IDOR/BOLA" in categories
    assert "Security Misconfiguration" in categories
    assert "Exposed Services" in categories
    assert "SSL/TLS Issues" in categories
    assert "SQL Injection" in categories
    assert "Secret Leak" in categories
    assert "SSRF" in categories
    assert "Broken Authentication" in categories
    assert "Path Traversal" in categories
    assert "Insecure Deserialization" in categories

def test_ai_pipeline_required_dimensions():
    """Verify that the AI engine generates all 7 required dimensions with valid schema."""
    async def _runner():
        runner = FindingsPipelineRunner("data/findings.json", provider="expert-engine")
        findings = runner.load_findings()

        # Test across all findings
        for finding in findings:
            enriched = await runner.analyze_single(finding)
            analysis = enriched.analysis
            assert analysis is not None
            
            # 1. Explanation
            assert isinstance(analysis.explanation, str) and len(analysis.explanation) > 20

            # 2. Impact
            assert isinstance(analysis.impact.technical_impact, str) and len(analysis.impact.technical_impact) > 10
            assert isinstance(analysis.impact.business_impact, str) and len(analysis.impact.business_impact) > 10
            assert isinstance(analysis.impact.blast_radius, str) and len(analysis.impact.blast_radius) > 5

            # 3. Evidence interpretation
            assert isinstance(analysis.evidence_interpretation, str) and len(analysis.evidence_interpretation) > 15

            # 4. Recommended remediation
            assert isinstance(analysis.recommended_remediation.immediate_mitigation, str) and len(analysis.recommended_remediation.immediate_mitigation) > 10
            assert isinstance(analysis.recommended_remediation.permanent_fix, str) and len(analysis.recommended_remediation.permanent_fix) > 10
            assert isinstance(analysis.recommended_remediation.verification_steps, str) and len(analysis.recommended_remediation.verification_steps) > 10

            # 5. Executive summary
            assert isinstance(analysis.executive_summary, str) and len(analysis.executive_summary) > 20

            # 6. Developer-oriented explanation
            assert isinstance(analysis.developer_oriented_explanation, str) and len(analysis.developer_oriented_explanation) > 20

            # 7. Confidence reasoning & score
            assert isinstance(analysis.confidence_reasoning, str) and len(analysis.confidence_reasoning) > 10
            assert 0.0 <= analysis.confidence_score <= 1.0
            assert analysis.confidence_rating in ["HIGH", "MEDIUM", "LOW"]

    asyncio.run(_runner())

def test_batch_report_and_exports(tmp_path):
    """Verify batch processing, metric calculations, and export generators."""
    async def _runner():
        runner = FindingsPipelineRunner("data/findings.json", provider="expert-engine")
        report = await runner.run_batch()
        
        assert isinstance(report, BatchReport)
        assert report.metrics.total_findings >= 15
        assert report.metrics.analyzed_findings == report.metrics.total_findings
        assert report.metrics.critical_or_high_count >= 10
        assert report.metrics.average_confidence >= 0.85

        # Test exports
        json_path = tmp_path / "test_report.json"
        runner.export_json(report, str(json_path))
        assert os.path.exists(json_path)

        md = runner.export_markdown(report)
        assert "# Cybersecurity AI Findings Analysis Report" in md
        assert "## Executive Summary & Metrics" in md
        assert "### [SEC-001]" in md

        html = runner.export_html(report)
        assert "<!DOCTYPE html>" in html
        assert "Cybersecurity AI Findings Analysis Report" in html

    asyncio.run(_runner())

def test_dynamic_custom_finding_analysis():
    """Verify that dynamic analysis works on ad-hoc custom findings."""
    async def _runner():
        engine = CybersecurityAIEngine(provider="expert-engine")
        custom_finding = SecurityFinding(
            id="CUSTOM-999",
            title="Prototype Pollution in Node.js Body Parser",
            category="Prototype Pollution",
            severity="HIGH",
            asset="api.custom-app.com",
            endpoint="POST /api/settings",
            timestamp="2026-09-18T12:00:00Z",
            evidence={
                "payload": '{"__proto__": {"isAdmin": true}}',
                "response": "Object.prototype.isAdmin polluted"
            }
        )

        analysis = await engine.analyze_finding(custom_finding)
        assert analysis.suggested_priority == "P1 - High"
        assert analysis.confidence_score >= 0.8
        assert "Prototype Pollution" in analysis.explanation
        assert len(analysis.executive_summary) > 10

    asyncio.run(_runner())

def test_api_endpoints():
    """Verify FastAPI endpoints return expected HTTP statuses and schemas."""
    # 1. GET findings
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) >= 15

    # 2. POST analyze single
    resp = client.post("/api/analyze/SEC-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["finding"]["id"] == "SEC-001"
    assert data["analysis"]["suggested_priority"] == "P0 - Critical"

    # 3. POST analyze custom
    custom_payload = {
        "title": "Unauthenticated Sentry Debug Endpoint",
        "category": "Exposed Services",
        "severity": "HIGH",
        "asset": "debug.internal.com",
        "endpoint": "GET /debug/sentry",
        "evidence": {"log": "Internal stack traces dumped"}
    }
    resp = client.post("/api/analyze-custom", json=custom_payload)
    assert resp.status_code == 200
    custom_res = resp.json()
    assert custom_res["finding"]["id"].startswith("CUSTOM-")
    assert custom_res["analysis"]["confidence_rating"] == "HIGH"

    # 4. GET exports
    resp_json = client.get("/api/export/json")
    assert resp_json.status_code == 200
    assert "findings" in resp_json.json()

    resp_md = client.get("/api/export/markdown")
    assert resp_md.status_code == 200
    assert resp_md.headers["content-type"].startswith("text/markdown")

    resp_html = client.get("/api/export/html")
    assert resp_html.status_code == 200
    assert resp_html.headers["content-type"].startswith("text/html")
