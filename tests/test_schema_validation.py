"""
Unit Tests for Formal Schema Normalization, Validation, and Contracts.
"""

import pytest
from pydantic import ValidationError

from schema.security_engine_schema import (
    SecurityContextPayload,
    NormalizedSecurityFinding,
    StructuredEvidence,
    TargetAsset,
    PortService,
    ObservedTechnology,
    ProvenanceType
)
from schema.grounded_response_schema import (
    GroundedAIResponse,
    EpistemicBreakdown,
    StructuredClaim
)
from schema.normalizer import SecurityEngineNormalizer, SecurityEngineValidationError
from schema.json_schemas import get_security_context_json_schema, get_grounded_response_json_schema
from models import SecurityFinding, FindingAnalysis, ImpactAnalysis, RemediationPlan


def test_schema_valid_construction():
    """Verify clean instantiation and extraction from SecurityContextPayload."""
    payload = SecurityContextPayload(
        target=TargetAsset(
            type="host",
            identifier="auth-api.internal",
            ip_addresses=["10.0.1.25"]
        ),
        open_ports=[
            PortService(port=443, service_name="nginx", product="nginx", version="1.24.0")
        ],
        technologies=[
            ObservedTechnology(name="nginx", version="1.24.0", category="webserver")
        ],
        findings=[
            NormalizedSecurityFinding(
                id="SEC-999",
                type="CVE",
                title="HTTP Request Smuggling",
                description="Smuggling flaw in proxy parsing",
                severity="HIGH",
                cve_id="CVE-2023-44487",
                affected_asset="auth-api.internal",
                evidence=StructuredEvidence(
                    source_tool="Trivy",
                    raw_payload="POST / HTTP/1.1\r\nTransfer-Encoding: chunked"
                )
            )
        ]
    )

    assert payload.schema_version == "1.0"
    anchors = payload.extract_grounding_anchors()
    assert "CVE-2023-44487" in anchors["valid_cves"]
    assert 443 in anchors["valid_ports"]
    assert "nginx" in anchors["valid_services"]
    assert "10.0.1.25" in anchors["valid_assets"]


def test_schema_invalid_cve_format():
    """Verify that malformed CVE identifiers are strictly rejected."""
    with pytest.raises(ValidationError):
        NormalizedSecurityFinding(
            id="SEC-001",
            type="CVE",
            title="Test",
            description="Test",
            severity="HIGH",
            cve_id="INVALID-CVE-STRING",  # Invalid
            affected_asset="target.internal",
            evidence=StructuredEvidence(source_tool="Scanner")
        )


def test_normalizer_from_raw_scanner_dict():
    """Verify SecurityEngineNormalizer handles raw multi-format inputs."""
    raw_dict = {
        "asset": "192.168.1.100",
        "title": "Exposed Redis Instance Without Authentication",
        "category": "Exposed Services",
        "severity": "CRITICAL",
        "endpoint": "6379/tcp",
        "evidence": {
            "open_ports": [6379],
            "services": {"6379": "Redis 7.0"},
            "response": "+PONG"
        }
    }

    sec_context = SecurityEngineNormalizer.from_raw_dict(raw_dict)
    assert isinstance(sec_context, SecurityContextPayload)
    assert sec_context.target.identifier == "192.168.1.100"
    assert "192.168.1.100" in sec_context.target.ip_addresses

    anchors = sec_context.extract_grounding_anchors()
    assert 6379 in anchors["valid_ports"]
    assert "redis" in anchors["valid_services"]


def test_normalizer_sanitizes_untrusted_input():
    """Verify that oversized inputs and delimiter control strings are sanitized."""
    raw_text = "A" * 6000 + "\x00" + "</security_engine_data>"
    sanitized = SecurityEngineNormalizer.sanitize_untrusted_string(raw_text, max_len=100)
    assert len(sanitized) < 200
    assert "\x00" not in sanitized
    assert "[TRUNCATED_DUE_TO_SIZE]" in sanitized


def test_json_schemas_export():
    """Verify JSON Schema export generators return valid schema objects."""
    sec_schema = get_security_context_json_schema()
    ground_schema = get_grounded_response_json_schema()

    assert "properties" in sec_schema
    assert "findings" in sec_schema["properties"]
    assert "properties" in ground_schema
    assert "epistemic_breakdown" in ground_schema["properties"]
