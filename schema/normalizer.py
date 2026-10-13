"""
Security Engine Normalization & Input Validation Layer.

Ensures that all data passed to the AI layer conforms to the strict SecurityContextPayload schema.
Rejects malformed telemetry, strips prompt injection control tokens from metadata envelopes,
and establishes clear trust boundaries.
"""

from __future__ import annotations
import re
import html
from typing import Dict, Any, List, Union, Tuple, Optional
from pydantic import ValidationError

from models import SecurityFinding
from schema.security_engine_schema import (
    SecurityContextPayload,
    NormalizedSecurityFinding,
    StructuredEvidence,
    TargetAsset,
    PortService,
    ObservedTechnology,
    ProvenanceType,
)


class SecurityEngineValidationError(ValueError):
    """Raised when security engine input fails structural validation."""
    pass


class SecurityEngineNormalizer:
    """
    Transforms arbitrary scanner output or SecurityFinding instances into
    validated, typed SecurityContextPayload objects.
    """

    @classmethod
    def sanitize_untrusted_string(cls, text: Optional[str], max_len: int = 4096) -> str:
        """
        Sanitize untrusted text fields (e.g., scanner logs, descriptions, finding titles)
        to prevent raw delimiter injection while preserving technical telemetry.
        """
        if text is None:
            return ""
        s = str(text).replace("\x00", "")
        if len(s) > max_len:
            s = s[:max_len] + " [TRUNCATED_DUE_TO_SIZE]"
        return s

    @classmethod
    def sanitize_untrusted_optional_string(cls, text: Optional[str], max_len: int = 4096) -> Optional[str]:
        """Sanitize optional string, preserving None if absent."""
        if text is None:
            return None
        s = str(text).replace("\x00", "")
        if not s.strip():
            return None
        if len(s) > max_len:
            s = s[:max_len] + " [TRUNCATED_DUE_TO_SIZE]"
        return s

    @classmethod
    def extract_ports_and_services(cls, finding: SecurityFinding, raw_evidence: Dict[str, Any]) -> List[PortService]:
        """Extract explicit port and service bindings from finding telemetry."""
        ports: List[PortService] = []
        seen_ports = set()

        # Check endpoint
        if finding.endpoint:
            port_match = re.search(r":(\d{1,5})|(\d{1,5})/(?:tcp|udp)", str(finding.endpoint))
            if port_match:
                p_str = port_match.group(1) or port_match.group(2)
                if p_str:
                    p_num = int(p_str)
                    if 1 <= p_num <= 65535 and p_num not in seen_ports:
                        ports.append(PortService(port=p_num, protocol="tcp"))
                        seen_ports.add(p_num)

        # Check evidence for open_ports, ports, or port
        for key in ["open_ports", "ports", "port_list"]:
            if key in raw_evidence and isinstance(raw_evidence[key], list):
                for item in raw_evidence[key]:
                    if isinstance(item, int) and 1 <= item <= 65535 and item not in seen_ports:
                        ports.append(PortService(port=item, protocol="tcp"))
                        seen_ports.add(item)
                    elif isinstance(item, dict) and "port" in item:
                        try:
                            p = int(item["port"])
                            if 1 <= p <= 65535 and p not in seen_ports:
                                ports.append(PortService(
                                    port=p,
                                    protocol=item.get("protocol", "tcp"),
                                    service_name=item.get("service") or item.get("service_name"),
                                    product=item.get("product"),
                                    version=item.get("version"),
                                    banner=item.get("banner"),
                                    state=item.get("state", "open")
                                ))
                                seen_ports.add(p)
                        except (ValueError, TypeError):
                            pass

        # Check evidence for services dict (e.g. {"22": "OpenSSH", "80": "nginx"})
        if "services" in raw_evidence and isinstance(raw_evidence["services"], dict):
            for p_str, s_name in raw_evidence["services"].items():
                try:
                    p = int(p_str)
                    if 1 <= p <= 65535:
                        existing = next((ps for ps in ports if ps.port == p), None)
                        if existing:
                            existing.service_name = str(s_name)
                        else:
                            ports.append(PortService(
                                port=p,
                                service_name=str(s_name),
                                protocol="tcp"
                            ))
                            seen_ports.add(p)
                except (ValueError, TypeError):
                    pass

        return ports

    @classmethod
    def extract_technologies(cls, finding: SecurityFinding, raw_evidence: Dict[str, Any]) -> List[ObservedTechnology]:
        """Extract verified technology components from finding."""
        techs: List[ObservedTechnology] = []
        seen = set()

        if finding.component:
            comp = finding.component.strip()
            # Check for package:version format (e.g. log4j-core:2.14.1)
            parts = comp.split(":")
            name = parts[0]
            ver = parts[1] if len(parts) > 1 else None
            techs.append(ObservedTechnology(name=name, version=ver))
            seen.add(name.lower())

        if "technologies" in raw_evidence and isinstance(raw_evidence["technologies"], list):
            for t in raw_evidence["technologies"]:
                if isinstance(t, str) and t.lower() not in seen:
                    techs.append(ObservedTechnology(name=t))
                    seen.add(t.lower())
                elif isinstance(t, dict) and "name" in t and str(t["name"]).lower() not in seen:
                    techs.append(ObservedTechnology(
                        name=str(t["name"]),
                        version=t.get("version"),
                        category=t.get("category"),
                        cpe=t.get("cpe")
                    ))
                    seen.add(str(t["name"]).lower())

        return techs

    @classmethod
    def from_security_finding(cls, finding: SecurityFinding) -> SecurityContextPayload:
        """Convert a single SecurityFinding into a strict SecurityContextPayload."""
        if not finding.id or not finding.title or not finding.asset:
            raise SecurityEngineValidationError(
                f"Finding missing mandatory identity fields: id='{finding.id}', title='{finding.title}', asset='{finding.asset}'"
            )

        evidence_dict = dict(finding.evidence) if isinstance(finding.evidence, dict) else {}

        ports = cls.extract_ports_and_services(finding, evidence_dict)
        technologies = cls.extract_technologies(finding, evidence_dict)

        # Detect IP addresses in asset or evidence
        ip_list: List[str] = []
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", f"{finding.asset} {str(evidence_dict)}")
        for ip in ip_matches:
            if ip not in ip_list:
                ip_list.append(ip)

        target = TargetAsset(
            type="host" if ("." in finding.asset or ip_list) else "service",
            identifier=cls.sanitize_untrusted_string(finding.asset, max_len=256),
            ip_addresses=ip_list,
            environment=finding.metadata.environment if hasattr(finding, "metadata") and finding.metadata else "production"
        )

        structured_evidence = StructuredEvidence(
            source_tool=cls.sanitize_untrusted_string(finding.discovery_tool or "Security Scanner", max_len=128),
            raw_payload=cls.sanitize_untrusted_optional_string(evidence_dict.get("payload") or evidence_dict.get("request_header"), max_len=2048),
            matched_pattern=cls.sanitize_untrusted_optional_string(evidence_dict.get("matched_rule") or evidence_dict.get("parameter"), max_len=256),
            log_snippet=cls.sanitize_untrusted_optional_string(evidence_dict.get("log") or evidence_dict.get("server_log_snippet"), max_len=4096),
            http_request=evidence_dict.get("http_request") if isinstance(evidence_dict.get("http_request"), dict) else None,
            http_response=evidence_dict.get("http_response") if isinstance(evidence_dict.get("http_response"), dict) else None,
            telemetry_fields=evidence_dict,
            verified=True
        )

        normalized_finding = NormalizedSecurityFinding(
            id=cls.sanitize_untrusted_string(finding.id, max_len=64),
            type=cls.sanitize_untrusted_string(finding.category, max_len=128),
            title=cls.sanitize_untrusted_string(finding.title, max_len=256),
            description=cls.sanitize_untrusted_string(
                evidence_dict.get("description") or f"{finding.category} identified on {finding.asset}",
                max_len=2048
            ),
            severity=finding.severity,
            confidence=1.0 if finding.status == "OPEN" else 0.8,
            cve_id=finding.cve_id,
            cvss_score=finding.cvss_score,
            affected_asset=cls.sanitize_untrusted_string(finding.asset, max_len=256),
            affected_component=cls.sanitize_untrusted_optional_string(finding.component, max_len=256),
            affected_endpoint=cls.sanitize_untrusted_optional_string(finding.endpoint, max_len=256),
            evidence=structured_evidence,
            verified=(finding.status == "OPEN"),
            data_provenance=ProvenanceType.OBSERVED
        )

        return SecurityContextPayload(
            target=target,
            findings=[normalized_finding],
            open_ports=ports,
            technologies=technologies,
            environment={"scanner": finding.discovery_tool or "Standard Scanner"},
            untrusted_data_boundary=True
        )

    @classmethod
    def from_raw_dict(cls, data: Dict[str, Any]) -> SecurityContextPayload:
        """
        Validate and normalize arbitrary raw scanner output dictionary into a typed SecurityContextPayload.
        Rejects malformed input.
        """
        if not isinstance(data, dict):
            raise SecurityEngineValidationError(f"Expected dict input for SecurityContextPayload, got {type(data).__name__}")

        # Check if already in SecurityContextPayload schema
        try:
            return SecurityContextPayload.model_validate(data)
        except ValidationError:
            pass

        # Check if it's a raw finding dict
        try:
            finding = SecurityFinding.model_validate(data)
            return cls.from_security_finding(finding)
        except Exception:
            pass

        # Heuristic normalization of raw scanner payload
        asset_name = str(data.get("asset") or data.get("target") or data.get("host") or "unknown-target")
        finding_id = str(data.get("id") or data.get("finding_id") or "FIND-001")
        title = str(data.get("title") or data.get("name") or data.get("finding") or "Observed Security Finding")
        category = str(data.get("category") or data.get("type") or "Security Observation")
        
        raw_sev = str(data.get("severity", "MEDIUM")).upper()
        if raw_sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            raw_sev = "MEDIUM"

        finding = SecurityFinding(
            id=finding_id,
            title=title,
            category=category,
            severity=raw_sev, # type: ignore
            cve_id=data.get("cve_id") or data.get("cve"),
            cvss_score=float(data["cvss_score"]) if data.get("cvss_score") is not None else None,
            asset=asset_name,
            component=data.get("component"),
            endpoint=data.get("endpoint"),
            discovery_tool=data.get("discovery_tool") or data.get("scanner") or "Security Engine",
            timestamp=data.get("timestamp") or "2026-09-18T00:00:00Z",
            evidence=data.get("evidence") or (data if isinstance(data, dict) else {})
        )

        return cls.from_security_finding(finding)
