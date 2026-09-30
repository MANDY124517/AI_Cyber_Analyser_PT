from __future__ import annotations
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
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


class RemediationPlan(BaseModel):
    immediate_mitigation: str = Field(..., description="Emergency containment step (WAF rule, config toggle, network block)")
    permanent_fix: str = Field(..., description="Comprehensive root-cause remediation steps")
    code_sample_patch: Optional[str] = Field(None, description="Concrete code diff, configuration snippet, or CLI command")
    verification_steps: str = Field(..., description="Actionable test commands or steps to verify the fix works")


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
