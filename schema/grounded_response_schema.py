"""
Formal Grounded AI Response Schema.
Version: 1.0

Requires explicit epistemic categorization:
- VERIFIED FACT: Directly grounded in observed security engine evidence
- INFERENCE: Logical deductions explicitly indicated as such
- ASSUMPTION: Hypotheses regarding unverified context
- UNKNOWN: Missing information or questions that cannot be verified from data
- RECOMMENDATION: Actionable remediation guidance
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, model_validator
from datetime import datetime, timezone
from models import FindingAnalysis, ImpactAnalysis, RemediationPlan
from grounding.guardian import GuardianAuditResult


class EpistemicCategory(str):
    VERIFIED_FACT = "VERIFIED FACT"
    INFERENCE = "INFERENCE"
    ASSUMPTION = "ASSUMPTION"
    UNKNOWN = "UNKNOWN"
    RECOMMENDATION = "RECOMMENDATION"


class StructuredClaim(BaseModel):
    """An individual atomic claim made in the AI analysis."""
    claim_text: str = Field(..., description="The concrete security assertion or observation")
    epistemic_type: Literal["VERIFIED FACT", "INFERENCE", "ASSUMPTION", "UNKNOWN", "RECOMMENDATION"] = Field(
        ..., description="Epistemic categorization of the claim"
    )
    evidence_reference: Optional[str] = Field(
        None, description="Path or key in security context telemetry supporting this claim (if verified)"
    )
    is_grounded: bool = Field(default=True, description="Whether claim is backed by provided facts")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in this atomic claim")


class EpistemicBreakdown(BaseModel):
    """Categorized claims ensuring clean separation of facts vs inferences."""
    verified_facts: List[str] = Field(
        default_factory=list,
        description="Factual assertions directly traceable to observed security engine telemetry"
    )
    inferences: List[str] = Field(
        default_factory=list,
        description="Logical deductions derived from facts, explicitly marked as inferences"
    )
    assumptions: List[str] = Field(
        default_factory=list,
        description="Hypotheses or assumed defaults when data is missing"
    )
    unknowns: List[str] = Field(
        default_factory=list,
        description="Explicitly identified unknowns, missing telemetry, or un-probed surfaces"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Recommended mitigation steps clearly labeled as advisory recommendations"
    )


class GroundingEvaluationSummary(BaseModel):
    """Evaluation metrics verifying whether the model followed grounding rules."""
    grounding_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Proportion of claims grounded in evidence")
    hallucination_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Proportion of invented or unsupported claims")
    unsupported_claims: List[str] = Field(default_factory=list, description="List of unverified assertions")
    supported_claims: List[str] = Field(default_factory=list, description="List of verified assertions")
    contradictions: List[str] = Field(default_factory=list, description="Direct contradictions of evidence")
    security_policy_violations: List[str] = Field(default_factory=list, description="Policy violations detected")
    prompt_injection_detected: bool = Field(default=False, description="Whether prompt injection payload was followed")
    evaluation_passed: bool = Field(default=True, description="Overall grounding pass/fail status")
    guardian_audit: Optional[GuardianAuditResult] = Field(
        None, description="Optional IBM Granite Guardian 3 safety and grounding verification audit"
    )


class GroundedAIResponse(BaseModel):
    """
    Formal Grounded AI Response Object.
    Combines the core dual-audience security analysis with epistemic segregation and grounding validation.
    """
    schema_version: str = Field(default="1.0", description="Schema version")
    finding_id: str = Field(..., description="ID of the analyzed finding")
    epistemic_breakdown: EpistemicBreakdown = Field(
        default_factory=EpistemicBreakdown,
        description="Strict separation of verified facts, inferences, assumptions, unknowns, and recommendations"
    )
    analysis: FindingAnalysis = Field(..., description="Complete 7-dimension security analysis")
    claims: List[StructuredClaim] = Field(
        default_factory=list, description="Atomic claims with evidence links and verification flags"
    )
    evaluation: Optional[GroundingEvaluationSummary] = Field(
        None, description="Grounding and hallucination evaluation results"
    )
    guardian_audit: Optional[GuardianAuditResult] = Field(
        None, description="IBM Granite Guardian 3 (8B) safety, grounding, and anti-jailbreak audit"
    )
    model_used: str = Field("ai-cyber-analyzer-v1", description="Ollama model or engine identifier")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Generation timestamp"
    )

