"""
Formal Versioned Schema for Security Engine -> AI Interface.
Version: 1.0

Distinguishes:
- Observed Data: Direct scanner or telemetry observation (ports, banners, raw payloads)
- Derived Data: Calculated metrics (e.g. CVSS, OWASP mapping)
- Inferred Data: AI or heuristic hypotheses
- Unknown Data: Explicitly missing or unverified information
- Recommendations: Actionable mitigation advice
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from datetime import datetime, timezone
import uuid


class ProvenanceType:
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    RECOMMENDATION = "RECOMMENDATION"


class TargetAsset(BaseModel):
    """Target asset under security evaluation."""
    type: Literal["host", "url", "container", "repository", "cloud_resource", "network", "service"] = Field(
        default="host", description="Asset archetype"
    )
    identifier: str = Field(..., description="Target hostname, IP, URL, ARN, or repo path")
    ip_addresses: List[str] = Field(default_factory=list, description="Explicitly verified IP addresses")
    environment: str = Field(default="production", description="Environment tier (production, staging, dev)")
    operating_system: Optional[str] = Field(None, description="Observed OS or kernel version if verified")


class PortService(BaseModel):
    """Observed open network port and service banner."""
    port: int = Field(..., ge=1, le=65535, description="Port number (1-65535)")
    protocol: Literal["tcp", "udp"] = "tcp"
    service_name: Optional[str] = Field(None, description="Observed service (e.g. OpenSSH, nginx, Redis)")
    product: Optional[str] = Field(None, description="Detected product/daemon name")
    version: Optional[str] = Field(None, description="Detected version string from banner")
    banner: Optional[str] = Field(None, description="Raw banner string captured by probe")
    state: Literal["open", "filtered", "closed"] = "open"


class ObservedTechnology(BaseModel):
    """Detected framework, library, package, or technology stack."""
    name: str = Field(..., description="Technology name (e.g., log4j, Spring, React)")
    version: Optional[str] = Field(None, description="Exact detected version string")
    category: Optional[str] = Field(None, description="Technology category (runtime, library, webserver)")
    cpe: Optional[str] = Field(None, description="Common Platform Enumeration string if available")


class StructuredEvidence(BaseModel):
    """Raw and structured evidence telemetry originating from security tools."""
    source_tool: str = Field(..., description="Discovery tool or sensor name (e.g. Trivy, OWASP ZAP, Burp, WAF)")
    raw_payload: Optional[str] = Field(None, description="Raw exploit payload, query, or injected string")
    matched_pattern: Optional[str] = Field(None, description="Matched signature or rule identifier")
    log_snippet: Optional[str] = Field(None, description="Relevant server log lines")
    http_request: Optional[Dict[str, Any]] = Field(None, description="Method, path, headers, body")
    http_response: Optional[Dict[str, Any]] = Field(None, description="Status code, headers, snippet")
    telemetry_fields: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary raw telemetry dictionary")
    verified: bool = Field(default=True, description="Whether telemetry was actively verified by scanner")


class NormalizedSecurityFinding(BaseModel):
    """Standardized finding record passed to the AI reasoning engine."""
    id: str = Field(..., description="Unique finding ID (e.g., SEC-001, FIND-842)")
    type: str = Field(..., description="Vulnerability category or finding type")
    title: str = Field(..., description="Concise human-readable finding title")
    description: str = Field(..., description="Technical summary of the finding from scanner")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] = Field(
        ..., description="Scanner-assigned finding severity"
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Scanner detection confidence (0.0 to 1.0)")
    cve_id: Optional[str] = Field(None, description="Verified CVE identifier (e.g., CVE-2021-44228)")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="Verified CVSS score")
    affected_asset: str = Field(..., description="Primary affected asset identifier")
    affected_component: Optional[str] = Field(None, description="Vulnerable component, library, or file")
    affected_endpoint: Optional[str] = Field(None, description="Affected URL endpoint, method, or port")
    evidence: StructuredEvidence = Field(..., description="Structured telemetry supporting this finding")
    references: List[str] = Field(default_factory=list, description="Verified documentation or advisory URLs")
    verified: bool = Field(default=True, description="Whether this finding represents an active confirmed flaw")
    data_provenance: str = Field(default=ProvenanceType.OBSERVED, description="Provenance classification")

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, v: Optional[str]) -> Optional[str]:
        if v:
            import re
            cleaned = v.strip().upper()
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cleaned):
                raise ValueError(f"Invalid CVE format: '{v}'. Must match 'CVE-YYYY-NNNN+'")
            return cleaned
        return None


class SecurityContextPayload(BaseModel):
    """
    Formal, Versioned Security Context Object.
    Contract between Security Engine -> Normalization/Validation -> AI Prompt Layer.
    """
    schema_version: str = Field(default="1.0", description="Schema version identifier")
    scan_id: str = Field(
        default_factory=lambda: f"SCAN-{uuid.uuid4().hex[:8].upper()}",
        description="Unique scan session ID"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Scan/context generation timestamp in UTC ISO format"
    )
    target: TargetAsset = Field(..., description="Target asset under analysis")
    findings: List[NormalizedSecurityFinding] = Field(
        default_factory=list, description="List of normalized security findings"
    )
    open_ports: List[PortService] = Field(
        default_factory=list, description="Explicitly observed open ports and services"
    )
    technologies: List[ObservedTechnology] = Field(
        default_factory=list, description="Detected technology stack and components"
    )
    environment: Dict[str, Any] = Field(
        default_factory=dict, description="Execution environment and network perimeter metadata"
    )
    known_limitations: List[str] = Field(
        default_factory=list, description="Scan scope constraints, un-probed endpoints, or rate limits"
    )
    untrusted_data_boundary: bool = Field(
        default=True, description="Flag designating all telemetry content as untrusted input"
    )

    def extract_grounding_anchors(self) -> Dict[str, Any]:
        """
        Deterministic Grounding Anchor Extractor.
        Builds the ground-truth facts table that the AI model must not hallucinate outside of.
        """
        ports = set()
        services = set()

        for p in self.open_ports:
            ports.add(p.port)
            if p.service_name:
                services.add(p.service_name.lower())
                for part in p.service_name.lower().split():
                    services.add(part)
            if p.product:
                services.add(p.product.lower())
                for part in p.product.lower().split():
                    services.add(part)

        cves = set()
        assets = {self.target.identifier.lower()}
        for ip in self.target.ip_addresses:
            assets.add(ip.lower())

        components = set()
        endpoints = set()
        discovery_tools = set()
        evidence_keys = set()
        severities = set()

        for f in self.findings:
            if f.cve_id:
                cves.add(f.cve_id.upper())
            if f.affected_asset:
                assets.add(f.affected_asset.lower())
            if f.affected_component:
                components.add(f.affected_component.lower())
            if f.affected_endpoint:
                endpoints.add(f.affected_endpoint.lower())
            if f.evidence.source_tool:
                discovery_tools.add(f.evidence.source_tool.lower())
            if f.severity:
                severities.add(f.severity.upper())
            for k in f.evidence.telemetry_fields.keys():
                evidence_keys.add(k.lower())

        technologies = set()
        for t in self.technologies:
            technologies.add(t.name.lower())
            services.add(t.name.lower())
            for part in t.name.lower().split():
                services.add(part)
            if t.version:
                technologies.add(f"{t.name.lower()} {t.version.lower()}")

        has_exploit_proof = any(
            (bool(f.evidence.raw_payload and f.evidence.raw_payload.strip())) or
            "exploit_confirmed" in str(f.evidence.telemetry_fields).lower() or
            "shell" in str(f.evidence.telemetry_fields).lower() or
            "unauthorized_access_confirmed" in str(f.evidence.telemetry_fields).lower()
            for f in self.findings
        )

        return {
            "valid_cves": list(cves),
            "valid_ports": [p.port for p in self.open_ports],
            "valid_services": list(services),
            "valid_assets": list(assets),
            "valid_components": list(components),
            "valid_endpoints": list(endpoints),
            "valid_technologies": list(technologies),
            "valid_discovery_tools": list(discovery_tools),
            "valid_severities": list(severities),
            "finding_count": len(self.findings),
            "has_exploitation_proof": has_exploit_proof
        }
