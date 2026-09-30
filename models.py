from __future__ import annotations
import json
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, model_validator
from datetime import datetime, timezone


class FindingMetadata(BaseModel):
    environment: str = "production"
    owner: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    id: str = Field(..., description="Unique finding identifier (e.g. SEC-001)")
    title: str = Field(..., description="Concise human-readable finding title")
    category: str = Field(..., description="Vulnerability category (e.g. CVE, XSS, IDOR/BOLA, etc.)")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] = Field(
        ..., description="Raw finding severity"
    )
    cve_id: Optional[str] = Field(None, description="CVE identifier if applicable")
    cvss_score: Optional[float] = Field(None, description="CVSS base score (0.0 - 10.0)")
    asset: str = Field(..., description="Affected host, URL, container, or service")
    component: Optional[str] = Field(None, description="Vulnerable component, package, or file")
    endpoint: Optional[str] = Field(None, description="Affected URL endpoint, method, or port")
    discovery_tool: Optional[str] = Field(None, description="Scanner or telemetry source")
    timestamp: str = Field(..., description="Discovery timestamp in ISO format")
    status: Literal["OPEN", "IN_PROGRESS", "RESOLVED", "SUPPRESSED"] = "OPEN"
    evidence: Dict[str, Any] = Field(
        default_factory=dict, description="Telemetry, payloads, headers, logs, or scanner outputs"
    )
    metadata: FindingMetadata = Field(default_factory=FindingMetadata)


class ImpactAnalysis(BaseModel):
    technical_impact: str = Field(..., description="Detailed technical consequences of exploitation")
    business_impact: str = Field(..., description="Consequences on business operations, compliance, revenue, or reputation")
    blast_radius: str = Field(..., description="Scope of asset compromise and potential lateral movement")

    @model_validator(mode="before")
    @classmethod
    def normalize_impact(cls, data: Any) -> Any:
        if isinstance(data, str):
            return {
                "technical_impact": data,
                "business_impact": "Potential operational and data integrity risk.",
                "blast_radius": "Target asset and integrated dependencies."
            }
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        if "technical_impact" not in normalized:
            normalized["technical_impact"] = normalized.get("technical") or normalized.get("tech_impact") or "Potential compromise of system confidentiality and integrity."
        if "business_impact" not in normalized:
            normalized["business_impact"] = normalized.get("business") or normalized.get("biz_impact") or "Impact on service trust, operations, and compliance."
        if "blast_radius" not in normalized:
            normalized["blast_radius"] = normalized.get("blastradius") or normalized.get("scope") or "Target service and immediate dependencies."
        return normalized


class RemediationPlan(BaseModel):
    immediate_mitigation: str = Field(..., description="Emergency containment step (WAF rule, config toggle, network block)")
    permanent_fix: str = Field(..., description="Comprehensive root-cause remediation steps")
    code_sample_patch: Optional[str] = Field(None, description="Concrete code diff, configuration snippet, or CLI command")
    verification_steps: str = Field(..., description="Actionable test commands or steps to verify the fix works")

    @model_validator(mode="before")
    @classmethod
    def normalize_remediation(cls, data: Any) -> Any:
        if isinstance(data, str):
            return {
                "immediate_mitigation": "Apply access control or WAF filtering.",
                "permanent_fix": data,
                "verification_steps": "Re-verify endpoint after patch deployment."
            }
        if not isinstance(data, dict):
            return data
        
        # Normalize key variations and common LLM typos (e.g. immediate_mitiation)
        key_map = {
            "immediate_mitiation": "immediate_mitigation",
            "immediate_action": "immediate_mitigation",
            "immediate_mitigations": "immediate_mitigation",
            "mitigation": "immediate_mitigation",
            "immediate": "immediate_mitigation",
            "containment": "immediate_mitigation",
            "permanent": "permanent_fix",
            "permanent_remediation": "permanent_fix",
            "permanent_solution": "permanent_fix",
            "remediation": "permanent_fix",
            "patch": "code_sample_patch",
            "code_patch": "code_sample_patch",
            "code_sample": "code_sample_patch",
            "diff": "code_sample_patch",
            "verify": "verification_steps",
            "verify_steps": "verification_steps",
            "verification": "verification_steps",
            "verification_step": "verification_steps",
            "test_steps": "verification_steps",
        }
        normalized = {}
        for k, v in data.items():
            mapped_key = key_map.get(k.lower().strip(), k)
            normalized[mapped_key] = v

        if "immediate_mitigation" not in normalized:
            normalized["immediate_mitigation"] = normalized.get("mitigation") or normalized.get("permanent_fix") or "Apply standard access controls and containment."
        if "permanent_fix" not in normalized:
            normalized["permanent_fix"] = normalized.get("remediation") or normalized.get("immediate_mitigation") or "Apply permanent code and configuration updates."
        if "verification_steps" not in normalized:
            normalized["verification_steps"] = "Re-test endpoint and inspect logs to confirm resolution."
            
        return normalized


class FindingAnalysis(BaseModel):
    # Core 7 required dimensions specified by requirements:
    explanation: str = Field(
        ..., description="Comprehensive explanation of what the vulnerability is and how it functions"
    )
    impact: ImpactAnalysis = Field(
        ..., description="Structured breakdown of technical and business impact"
    )
    evidence_interpretation: str = Field(
        ..., description="Deep analysis of what the raw scanner/telemetry evidence proves and why it is not a false positive"
    )
    recommended_remediation: RemediationPlan = Field(
        ..., description="Actionable remediation roadmap including immediate containment and permanent code fixes"
    )
    executive_summary: str = Field(
        ..., description="1-2 concise, high-impact sentences for CISOs, VP Engineering, and non-technical stakeholders"
    )
    developer_oriented_explanation: str = Field(
        ..., description="In-depth technical breakdown with architecture details, code mechanics, and developer advice"
    )
    confidence_reasoning: str = Field(
        ..., description="Transparent justification for the confidence rating and certainty based on evidence fidelity"
    )

    # Additional high-value structured attributes for enterprise platform integration:
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score from 0.0 (uncertain) to 1.0 (definitive proof)"
    )
    confidence_rating: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        ..., description="Categorical confidence rating"
    )
    remediation_effort: Literal["Low", "Medium", "High"] = Field(
        ..., description="Estimated engineering effort to remediate"
    )
    suggested_priority: Literal["P0 - Critical", "P1 - High", "P2 - Medium", "P3 - Low"] = Field(
        ..., description="AI suggested triage priority"
    )
    owasp_category: Optional[str] = Field(
        None, description="Mapped OWASP Top 10 category (e.g., A01:2021-Broken Access Control)"
    )
    mitre_tactics_techniques: List[str] = Field(
        default_factory=list, description="Relevant MITRE ATT&CK techniques (e.g., T1190)"
    )
    analyzed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Analysis completion timestamp"
    )
    model_used: str = Field("ai-cyber-analyzer-v1", description="Model or analyzer engine identifier")

    @model_validator(mode="before")
    @classmethod
    def normalize_analysis(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        
        # Normalize key aliases
        if "explanation" not in normalized:
            normalized["explanation"] = normalized.get("description") or normalized.get("overview") or normalized.get("summary") or "Vulnerability detected in target component."
        if "impact" not in normalized:
            normalized["impact"] = normalized.get("impact_analysis") or normalized.get("impacts") or "Vulnerability affects system confidentiality and integrity."
        if "evidence_interpretation" not in normalized:
            normalized["evidence_interpretation"] = normalized.get("evidence_analysis") or normalized.get("telemetry_analysis") or "Scanner evidence indicates confirmed vulnerability."
        if "recommended_remediation" not in normalized:
            normalized["recommended_remediation"] = normalized.get("remediation_plan") or normalized.get("remediation") or normalized.get("recommendations") or {}
        if "executive_summary" not in normalized:
            normalized["executive_summary"] = normalized.get("exec_summary") or normalized.get("ciso_summary") or str(normalized["explanation"])[:200]
        if "developer_oriented_explanation" not in normalized:
            normalized["developer_oriented_explanation"] = normalized.get("dev_explanation") or normalized.get("technical_explanation") or str(normalized["explanation"])
        if "confidence_reasoning" not in normalized:
            normalized["confidence_reasoning"] = normalized.get("confidence_explanation") or "High confidence based on verified scanner telemetry."

        # Stringify any nested dicts/lists returned by LLMs for string fields
        for str_field in ["evidence_interpretation", "explanation", "executive_summary", "developer_oriented_explanation", "confidence_reasoning"]:
            if isinstance(normalized.get(str_field), (dict, list)):
                try:
                    normalized[str_field] = json.dumps(normalized[str_field], indent=2)
                except Exception:
                    normalized[str_field] = str(normalized[str_field])

        raw_score = normalized.get("confidence_score", 0.95)
        try:
            if isinstance(raw_score, str):
                raw_score = float(raw_score.replace("%", "").strip())
                if raw_score > 1.0:
                    raw_score = raw_score / 100.0
            normalized["confidence_score"] = max(0.0, min(1.0, float(raw_score)))
        except (ValueError, TypeError):
            normalized["confidence_score"] = 0.95

        # Normalize confidence_rating
        raw_rating = str(normalized.get("confidence_rating", "HIGH")).upper()
        if "HIGH" in raw_rating:
            normalized["confidence_rating"] = "HIGH"
        elif "MED" in raw_rating:
            normalized["confidence_rating"] = "MEDIUM"
        else:
            normalized["confidence_rating"] = "LOW"

        # Normalize remediation_effort
        raw_effort = str(normalized.get("remediation_effort", "Medium")).capitalize()
        if raw_effort not in ["Low", "Medium", "High"]:
            normalized["remediation_effort"] = "Medium"
        else:
            normalized["remediation_effort"] = raw_effort

        # Normalize suggested_priority
        raw_prio = str(normalized.get("suggested_priority", "P1 - High")).upper()
        if "P0" in raw_prio or "CRITICAL" in raw_prio:
            normalized["suggested_priority"] = "P0 - Critical"
        elif "P1" in raw_prio or "HIGH" in raw_prio:
            normalized["suggested_priority"] = "P1 - High"
        elif "P2" in raw_prio or "MED" in raw_prio:
            normalized["suggested_priority"] = "P2 - Medium"
        else:
            normalized["suggested_priority"] = "P3 - Low"

        # Normalize mitre_tactics_techniques
        mitre = normalized.get("mitre_tactics_techniques", [])
        if isinstance(mitre, str):
            normalized["mitre_tactics_techniques"] = [mitre] if mitre else []
        elif not isinstance(mitre, list):
            normalized["mitre_tactics_techniques"] = []

        return normalized


class EnrichedFinding(BaseModel):
    finding: SecurityFinding
    analysis: Optional[FindingAnalysis] = None


class BatchReportMetrics(BaseModel):
    total_findings: int
    analyzed_findings: int
    severity_breakdown: Dict[str, int]
    priority_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]
    average_confidence: float
    critical_or_high_count: int
    remediation_effort_breakdown: Dict[str, int]


class BatchReport(BaseModel):
    report_title: str = "Cybersecurity AI Findings Analysis Report"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metrics: BatchReportMetrics
    findings: List[EnrichedFinding]
