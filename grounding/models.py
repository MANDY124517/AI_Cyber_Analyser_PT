"""
Grounding Evaluation Data Models & Policy Violations.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class GroundingRuleViolation(BaseModel):
    """Specific rule violation detected during deterministic grounding evaluation."""
    rule_id: str = Field(..., description="Identifier of the violated rule (e.g. RULE-03-CVE)")
    rule_name: str = Field(..., description="Short title of the rule")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(..., description="Severity of violation")
    description: str = Field(..., description="Detailed description of why the claim violated this rule")
    offending_claim: Optional[str] = Field(None, description="Exact claim or text snippet from AI response")
    expected_evidence: Optional[str] = Field(None, description="Evidence anchor required to support claim")
    remedy: str = Field(..., description="Actionable recommendation for model alignment")


class GroundingEvaluationResult(BaseModel):
    """Structured evaluation result produced by the Grounding Evaluator."""
    grounding_score: float = Field(..., ge=0.0, le=1.0, description="1.0 = fully grounded, 0.0 = completely hallucinated")
    hallucination_score: float = Field(..., ge=0.0, le=1.0, description="1.0 = completely fabricated, 0.0 = zero hallucinations")
    unsupported_claims: List[str] = Field(default_factory=list, description="List of unverified technical claims")
    supported_claims: List[str] = Field(default_factory=list, description="List of verified claims backed by evidence")
    contradictions: List[str] = Field(default_factory=list, description="Direct contradictions of provided facts")
    inferences: List[str] = Field(default_factory=list, description="Identified logical inferences")
    unknowns: List[str] = Field(default_factory=list, description="Properly labeled unknown / missing fields")
    security_policy_violations: List[str] = Field(default_factory=list, description="Summarized violation strings")
    detailed_violations: List[GroundingRuleViolation] = Field(default_factory=list, description="Structured rule violations")
    prompt_injection_detected: bool = Field(default=False, description="Whether prompt injection in telemetry was followed")
    evaluation_passed: bool = Field(default=True, description="True if grounding score >= threshold and no critical violations")
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    model_identifier: Optional[str] = None
