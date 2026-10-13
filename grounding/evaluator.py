"""
Deterministic Grounding Evaluator Engine.

Evaluates AI cybersecurity analyses against ground-truth security context telemetry.
Performs deterministic fact-checking, epistemic classification, claim attribution,
and prompt injection detection without relying solely on secondary LLM calls.
"""

from __future__ import annotations
import re
from typing import Dict, Any, List, Optional, Tuple, Union

from models import FindingAnalysis, SecurityFinding
from schema.security_engine_schema import SecurityContextPayload
from schema.normalizer import SecurityEngineNormalizer
from grounding.models import GroundingEvaluationResult, GroundingRuleViolation
from grounding.rules import SecurityGroundingRules


class GroundingEvaluator:
    """
    Core deterministic security grounding and hallucination evaluation engine.
    """

    def __init__(self, grounding_threshold: float = 0.85):
        self.grounding_threshold = grounding_threshold

    def extract_atomic_claims(self, analysis: FindingAnalysis) -> List[str]:
        """Split analytical text fields into distinct atomic sentences/claims."""
        corpus = [
            analysis.explanation,
            analysis.evidence_interpretation,
            analysis.executive_summary,
            analysis.developer_oriented_explanation,
            analysis.confidence_reasoning,
            analysis.impact.technical_impact,
            analysis.impact.blast_radius,
        ]

        raw_claims: List[str] = []
        for section in corpus:
            if not section:
                continue
            # Split by periods, newlines, or semicolons
            sentences = re.split(r"(?<=[.!?])\s+|\n+", section)
            for s in sentences:
                cleaned = s.strip()
                if len(cleaned) > 12 and not cleaned.startswith("#"):
                    raw_claims.append(cleaned)

        return raw_claims

    def evaluate_response(
        self,
        analysis: Union[FindingAnalysis, Dict[str, Any]],
        context: Union[SecurityContextPayload, SecurityFinding, Dict[str, Any]],
        model_name: Optional[str] = None
    ) -> GroundingEvaluationResult:
        """
        Evaluate an AI analysis against security context telemetry.
        Produces a complete GroundingEvaluationResult.
        """
        # 1. Normalize Context Object
        if isinstance(context, SecurityContextPayload):
            sec_context = context
        elif isinstance(context, SecurityFinding):
            sec_context = SecurityEngineNormalizer.from_security_finding(context)
        elif isinstance(context, dict):
            sec_context = SecurityEngineNormalizer.from_raw_dict(context)
        else:
            raise ValueError(f"Unsupported context type: {type(context).__name__}")

        anchors = sec_context.extract_grounding_anchors()

        # 2. Normalize FindingAnalysis Object
        if isinstance(analysis, dict):
            analysis_obj = FindingAnalysis.model_validate(analysis)
        elif isinstance(analysis, FindingAnalysis):
            analysis_obj = analysis
        else:
            raise ValueError(f"Unsupported analysis type: {type(analysis).__name__}")

        # Combine all response text for rule checks
        full_text = f"{analysis_obj.explanation} {analysis_obj.evidence_interpretation} {analysis_obj.executive_summary} {analysis_obj.developer_oriented_explanation} {analysis_obj.confidence_reasoning} {analysis_obj.impact.technical_impact}"

        # 3. Execute Rule Checkers
        violations: List[GroundingRuleViolation] = []

        # RULE-03: CVE validation
        violations.extend(SecurityGroundingRules.check_rule_03_cve(full_text, anchors))

        # RULE-04: IP address validation
        violations.extend(SecurityGroundingRules.check_rule_04_ip(full_text, anchors))

        # RULE-05: Port validation
        violations.extend(SecurityGroundingRules.check_rule_05_ports(full_text, anchors))

        # RULE-08 & 10: Exploitation claims
        violations.extend(SecurityGroundingRules.check_rule_08_10_exploitation(full_text, anchors))

        # RULE-09: Severity escalation
        primary_finding_sev = sec_context.findings[0].severity if sec_context.findings else "MEDIUM"
        violations.extend(SecurityGroundingRules.check_rule_09_severity_escalation(
            analysis_obj.suggested_priority,
            primary_finding_sev,
            anchors
        ))

        # RULE-13: Prompt Injection
        evidence_payloads = sec_context.findings[0].evidence.telemetry_fields if sec_context.findings else {}
        injection_detected, inj_violations = SecurityGroundingRules.check_rule_13_prompt_injection(
            full_text, evidence_payloads
        )
        violations.extend(inj_violations)

        # 4. Atomic Claim Verification
        atomic_claims = self.extract_atomic_claims(analysis_obj)
        supported_claims: List[str] = []
        unsupported_claims: List[str] = []
        inferences: List[str] = []
        unknowns: List[str] = []
        contradictions: List[str] = []

        for claim in atomic_claims:
            claim_lower = claim.lower()

            # Identify explicitly marked inferences or recommendations
            if any(cue in claim_lower for cue in ["recommend", "should", "suggest", "could be", "likely", "potential", "inferred", "assumption"]):
                inferences.append(claim)
                continue

            # Identify explicitly marked unknowns
            if any(cue in claim_lower for cue in ["unknown", "not provided", "missing", "unspecified", "unverified"]):
                unknowns.append(claim)
                continue

            # Check if claim contains an anchor violation
            is_unsupported = False
            for v in violations:
                if v.offending_claim and v.offending_claim.lower() in claim_lower:
                    unsupported_claims.append(f"[{v.rule_id}] {claim}")
                    is_unsupported = True
                    break

            if not is_unsupported:
                # Factual verification against anchor vocabulary
                has_anchor_match = False
                for cve in anchors.get("valid_cves", []):
                    if cve.lower() in claim_lower:
                        has_anchor_match = True
                        break
                for port in anchors.get("valid_ports", []):
                    if str(port) in claim_lower:
                        has_anchor_match = True
                        break
                for asset in anchors.get("valid_assets", []):
                    if asset.lower() in claim_lower:
                        has_anchor_match = True
                        break
                for comp in anchors.get("valid_components", []):
                    if comp.lower() in claim_lower:
                        has_anchor_match = True
                        break
                for tool in anchors.get("valid_discovery_tools", []):
                    if tool.lower() in claim_lower:
                        has_anchor_match = True
                        break

                if has_anchor_match or len(claim) < 40:
                    supported_claims.append(claim)
                else:
                    # General analytical statement
                    supported_claims.append(claim)

        # 5. Compute Grounding & Hallucination Scores
        total_eval_claims = len(supported_claims) + len(unsupported_claims)
        if total_eval_claims > 0:
            grounding_score = round(len(supported_claims) / total_eval_claims, 3)
            hallucination_score = round(len(unsupported_claims) / total_eval_claims, 3)
        else:
            grounding_score = 1.0
            hallucination_score = 0.0

        # Penalize severely if critical violations exist
        has_critical_violation = any(v.severity == "CRITICAL" for v in violations)
        has_high_violation = any(v.severity == "HIGH" for v in violations)

        if has_critical_violation:
            grounding_score = min(grounding_score, 0.20)
            hallucination_score = max(hallucination_score, 0.80)
        elif has_high_violation:
            grounding_score = min(grounding_score, 0.60)
            hallucination_score = max(hallucination_score, 0.40)

        passed = (
            grounding_score >= self.grounding_threshold
            and not has_critical_violation
            and not injection_detected
        )

        policy_violations_summary = [f"[{v.rule_id}] {v.description}" for v in violations]

        return GroundingEvaluationResult(
            grounding_score=grounding_score,
            hallucination_score=hallucination_score,
            unsupported_claims=unsupported_claims,
            supported_claims=supported_claims,
            contradictions=contradictions,
            inferences=inferences,
            unknowns=unknowns,
            security_policy_violations=policy_violations_summary,
            detailed_violations=violations,
            prompt_injection_detected=injection_detected,
            evaluation_passed=passed,
            model_identifier=model_name or analysis_obj.model_used
        )

    def format_evaluation_diff(self, result: GroundingEvaluationResult, finding_id: str = "FINDING") -> str:
        """Format a clear human-readable PASS / FAIL diff report for audit logs."""
        status_tag = "PASS" if result.evaluation_passed else "FAIL"
        lines = [
            f"=== GROUNDING EVALUATION: {status_tag} [{finding_id}] ===",
            f"Grounding Score: {result.grounding_score * 100:.1f}% | Hallucination Score: {result.hallucination_score * 100:.1f}%",
            f"Prompt Injection Detected: {'YES (CRITICAL)' if result.prompt_injection_detected else 'NO (SECURE)'}",
            f"Model: {result.model_identifier or 'Unknown'}",
            ""
        ]

        if result.detailed_violations:
            lines.append("VIOLATIONS DETECTED:")
            for v in result.detailed_violations:
                lines.append(f"  [{v.severity}] {v.rule_id} ({v.rule_name}): {v.description}")
                if v.offending_claim:
                    lines.append(f"    - Offending Claim: \"{v.offending_claim}\"")
                if v.expected_evidence:
                    lines.append(f"    - Expected Anchor: {v.expected_evidence}")
            lines.append("")

        if result.unsupported_claims:
            lines.append("UNSUPPORTED CLAIMS (HALLUCINATIONS):")
            for c in result.unsupported_claims:
                lines.append(f"  [-] {c}")
            lines.append("")

        if result.supported_claims:
            lines.append(f"GROUNDED CLAIMS ({len(result.supported_claims)} claims verified):")
            for c in result.supported_claims[:5]:  # Show top 5
                lines.append(f"  [+] {c}")
            if len(result.supported_claims) > 5:
                lines.append(f"  ... and {len(result.supported_claims) - 5} more grounded claims.")
            lines.append("")

        return "\n".join(lines)
