"""
JSON Schema Exporter and Contract Specifications for Security Engine -> AI Interface.
"""

from __future__ import annotations
import json
from typing import Dict, Any
from schema.security_engine_schema import SecurityContextPayload
from schema.grounded_response_schema import GroundedAIResponse


def get_security_context_json_schema() -> Dict[str, Any]:
    """Return JSON Schema dict for SecurityContextPayload (Draft 2020-12 / OpenAPI compatible)."""
    return SecurityContextPayload.model_json_schema()


def get_grounded_response_json_schema() -> Dict[str, Any]:
    """Return JSON Schema dict for GroundedAIResponse."""
    return GroundedAIResponse.model_json_schema()


SECURITY_CONTEXT_CONTRACT_DOC = """
# Security Context Contract Specification (v1.0)

## 1. Data Flow Pipeline
1. Security Engine / Scanner produces telemetry (Trivy, OWASP ZAP, Burp Suite, Nmap, Gitleaks, etc.)
2. `SecurityEngineNormalizer` validates structure, extracts anchors, and sanitizes untrusted input.
3. `SecurityContextPayload` wraps verified telemetry with strict untrusted data boundaries.
4. AI Prompt Template isolates instructions from untrusted data using explicit delimiter tags.
5. Ollama / LLM generates structured `GroundedAIResponse`.
6. `GroundingEvaluator` deterministically verifies all claims against original evidence anchors.

## 2. Mandatory vs Optional Fields

### Mandatory Fields in SecurityContextPayload:
- `schema_version`: String (e.g. "1.0")
- `scan_id`: String unique identifier
- `timestamp`: UTC ISO 8601 string
- `target`: TargetAsset with `identifier` and `type`
- `findings`: List of NormalizedSecurityFinding items

### Finding Mandatory Fields:
- `id`: Finding identifier (e.g., "SEC-001")
- `type`: Categorization (e.g., "CVE", "XSS", "SQL Injection")
- `title`: Human-readable title
- `severity`: One of CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
- `affected_asset`: Asset identifier
- `evidence`: StructuredEvidence object

### Optional / Extracted Fields:
- `cve_id`: Must strictly match regex `^CVE-\\d{4}-\\d{4,}$` if present
- `cvss_score`: Float between 0.0 and 10.0
- `open_ports`: Explicit list of observed open ports (1-65535) and service banners
- `technologies`: Verified software packages and versions
- `affected_endpoint`: Target URL, route, or port
- `affected_component`: Vulnerable library/module

## 3. Trust Boundary Model
- System instructions & Security Policy: **TRUSTED (System Domain)**
- Scanner output, logs, payloads, descriptions: **UNTRUSTED (External Data Domain)**
- Security engine telemetry MUST NEVER override system prompt instructions.
"""
