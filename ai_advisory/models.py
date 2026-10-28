from __future__ import annotations
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, model_validator
from datetime import datetime, timezone


class ThreatIntelData(BaseModel):
    """Real-world threat intelligence signals for a specific vulnerability/CVE."""
    cve_id: Optional[str] = Field(None, description="CVE identifier (e.g., CVE-2021-44228)")
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS 30-day exploit probability (0.0 - 1.0)")
    epss_percentile: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS percentile relative to all CVEs")
    cisa_kev_listed: bool = Field(False, description="Whether vulnerability is listed in CISA KEV catalog")
    cisa_date_added: Optional[str] = Field(None, description="Date CISA added finding to KEV")
    cisa_due_date: Optional[str] = Field(None, description="Federal compliance due date for remediation")
    cisa_vulnerability_name: Optional[str] = Field(None, description="Vulnerability name per CISA KEV catalog")
    known_ransomware_campaign: bool = Field(False, description="Known active use in ransomware campaigns")
    intel_source: str = Field("FIRST.org EPSS + CISA KEV", description="Threat intelligence provider")
    query_status: Literal["LIVE_API", "OFFLINE_CACHE", "NOT_APPLICABLE", "API_ERROR"] = Field(
        "LIVE_API", description="Status of the intelligence lookup"
    )
    queried_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AssetContext(BaseModel):
    """Contextual business and infrastructure posture of the affected asset."""
    asset_id: str = Field(..., description="Target hostname, IP, container, or service")
    environment: Literal["production", "staging", "development"] = Field(
        "production", description="Environment tier"
    )
    internet_facing: bool = Field(
        True, description="Whether the asset is directly exposed to the public internet"
    )
    business_criticality: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        "HIGH", description="Asset importance to business operations"
    )
    data_classification: Literal["RESTRICTED_PII", "CONFIDENTIAL", "INTERNAL", "PUBLIC"] = Field(
        "CONFIDENTIAL", description="Sensitivity of data processed or stored"
    )


class PrioritizationResult(BaseModel):
    """Deterministic, auditable prioritization score based on CVSS + EPSS + KEV + Asset Context."""
    priority_tier: Literal[
        "P0 - Immediate Action Required",
        "P1 - High Priority Patch",
        "P2 - Scheduled Sprint Fix",
        "P3 - Informational / Risk Accepted"
    ] = Field(..., description="Standardized triage priority band")
    composite_risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Deterministic risk score out of 100"
    )
    ssvc_decision: Literal["ACT", "ATTEND", "TRACK_STAR", "TRACK"] = Field(
        ..., description="CISA Stakeholder-Specific Vulnerability Categorization status"
    )
    remediation_sla_hours: int = Field(
        ..., description="Recommended remediation SLA in hours"
    )
    cvss_score: Optional[float] = Field(None, description="Base CVSS score (0.0 - 10.0)")
    epss_score: Optional[float] = Field(None, description="EPSS probability (0.0 - 1.0)")
    cisa_kev_listed: bool = Field(False, description="CISA KEV weaponization flag")
    scoring_breakdown: Dict[str, Any] = Field(
        default_factory=dict, description="Detailed mathematical weights and factor sub-scores"
    )
    decision_rationale: str = Field(
        ..., description="Deterministic audit rationale explaining the calculated priority"
    )


class AdvisoryNarrative(BaseModel):
    """Schema-constrained AI narrative explaining the prioritization to stakeholders."""
    executive_headline: str = Field(
        ..., description="Punchy, non-technical headline for leadership (CISO / Engineering VP)"
    )
    prioritization_justification: str = Field(
        ..., description="Plain-language justification citing EPSS %, KEV, and asset exposure"
    )
    exploitability_assessment: str = Field(
        ..., description="Contrast between theoretical severity (CVSS) and proven real-world threat"
    )
    asset_exposure_context: str = Field(
        ..., description="How asset environment and internet exposure influenced the rating"
    )
    action_recommendation: str = Field(
        ..., description="Direct guidance on whether to drop everything or schedule for normal sprint"
    )


class AdvisoryFindingReport(BaseModel):
    """Full advisory record combining raw finding, live intel, deterministic score, and AI narrative."""
    finding_id: str
    title: str
    category: str
    severity: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    asset: str
    threat_intel: ThreatIntelData
    asset_context: AssetContext
    prioritization: PrioritizationResult
    narrative: Optional[AdvisoryNarrative] = None
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AdvisoryBatchReport(BaseModel):
    """Aggregated advisory report for an entire scan or inventory batch."""
    report_title: str = "AI Advisory Threat Intelligence & Risk Prioritization Report"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_findings: int
    p0_immediate_count: int
    p1_high_count: int
    p2_medium_count: int
    p3_low_count: int
    cisa_kev_active_count: int
    high_epss_count: int
    findings: List[AdvisoryFindingReport]
