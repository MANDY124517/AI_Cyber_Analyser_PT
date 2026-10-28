from __future__ import annotations
from typing import Dict, Any, Optional
from ..models import ThreatIntelData, AssetContext, PrioritizationResult


class PrioritizationEngine:
    """
    Deterministic, mathematical risk prioritization engine implementing SSVC decision
    trees and weighted real-world risk formulas (CVSS + EPSS + CISA KEV + Asset Exposure).
    """

    # Scoring weights (sum to 1.0)
    WEIGHT_REAL_EXPLOIT = 0.40   # EPSS + KEV (Real-world threat)
    WEIGHT_IMPACT = 0.30         # CVSS / Raw Severity (Technical impact)
    WEIGHT_EXPOSURE = 0.20       # Internet-facing & Environment
    WEIGHT_ASSET_CRITICALITY = 0.10  # Business & Data tier

    def calculate_priority(
        self,
        cvss_score: Optional[float],
        severity: str,
        threat_intel: ThreatIntelData,
        asset_context: AssetContext,
        evidence: Optional[Dict[str, Any]] = None
    ) -> PrioritizationResult:
        """
        Compute deterministic composite risk score and SSVC decision band.
        """
        # 1. Normalize Base Impact Score (0.0 - 100.0)
        impact_score = self._compute_impact_score(cvss_score, severity)

        # 2. Compute Real-World Exploitability Score (0.0 - 100.0)
        exploit_score, exploit_state = self._compute_exploit_score(
            threat_intel, evidence, severity
        )

        # 3. Compute Exposure & Environment Score (0.0 - 100.0)
        exposure_score = self._compute_exposure_score(asset_context)

        # 4. Compute Business Criticality Score (0.0 - 100.0)
        criticality_score = self._compute_criticality_score(asset_context)

        # 5. Calculate Weighted Composite Score
        composite_score = round(
            (impact_score * self.WEIGHT_IMPACT) +
            (exploit_score * self.WEIGHT_REAL_EXPLOIT) +
            (exposure_score * self.WEIGHT_EXPOSURE) +
            (criticality_score * self.WEIGHT_ASSET_CRITICALITY),
            2
        )
        composite_score = max(0.0, min(100.0, composite_score))

        # 6. Apply SSVC Decision Tree
        ssvc_decision, priority_tier, sla_hours = self._evaluate_ssvc(
            exploit_state=exploit_state,
            internet_facing=asset_context.internet_facing,
            environment=asset_context.environment,
            composite_score=composite_score,
            cisa_kev_listed=threat_intel.cisa_kev_listed
        )

        # 7. Generate transparent audit rationale
        rationale = self._generate_decision_rationale(
            cvss_score=cvss_score,
            threat_intel=threat_intel,
            asset_context=asset_context,
            composite_score=composite_score,
            priority_tier=priority_tier,
            ssvc_decision=ssvc_decision
        )

        breakdown = {
            "impact_subscore": impact_score,
            "exploit_subscore": exploit_score,
            "exposure_subscore": exposure_score,
            "criticality_subscore": criticality_score,
            "weights": {
                "exploit_weight": self.WEIGHT_REAL_EXPLOIT,
                "impact_weight": self.WEIGHT_IMPACT,
                "exposure_weight": self.WEIGHT_EXPOSURE,
                "criticality_weight": self.WEIGHT_ASSET_CRITICALITY,
            },
            "exploit_state": exploit_state,
        }

        return PrioritizationResult(
            priority_tier=priority_tier,
            composite_risk_score=composite_score,
            ssvc_decision=ssvc_decision,
            remediation_sla_hours=sla_hours,
            cvss_score=cvss_score,
            epss_score=threat_intel.epss_score,
            cisa_kev_listed=threat_intel.cisa_kev_listed,
            scoring_breakdown=breakdown,
            decision_rationale=rationale
        )

    def _compute_impact_score(self, cvss_score: Optional[float], severity: str) -> float:
        if cvss_score is not None and cvss_score > 0.0:
            return round(cvss_score * 10.0, 1)

        sev_map = {
            "CRITICAL": 95.0,
            "HIGH": 75.0,
            "MEDIUM": 50.0,
            "LOW": 25.0,
            "INFORMATIONAL": 10.0
        }
        return sev_map.get(severity.upper(), 50.0)

    def _compute_exploit_score(
        self,
        threat_intel: ThreatIntelData,
        evidence: Optional[Dict[str, Any]],
        severity: str
    ) -> tuple[float, str]:
        """
        Returns (exploit_score: float, exploit_state: str).
        exploit_state is one of: 'ACTIVE_WEAPONIZED', 'HIGH_PROBABILITY', 'POC_EXISTS', 'LOW_UNLIKELY'.
        """
        # Case A: Known Exploited in the Wild (CISA KEV)
        if threat_intel.cisa_kev_listed:
            bonus = 10.0 if threat_intel.known_ransomware_campaign else 0.0
            return min(100.0, 90.0 + bonus), "ACTIVE_WEAPONIZED"

        # Case B: High EPSS Probability
        if threat_intel.epss_score is not None:
            epss = threat_intel.epss_score
            if epss >= 0.50:
                return round(75.0 + (epss * 20.0), 1), "HIGH_PROBABILITY"
            elif epss >= 0.15:
                return round(50.0 + (epss * 100.0), 1), "POC_EXISTS"
            else:
                # Low EPSS even if high CVSS
                return round(epss * 100.0, 1), "LOW_UNLIKELY"

        # Case C: Non-CVE finding with verified scanner exploit telemetry (PoC payload executed)
        has_verified_poc = False
        if evidence:
            indicators = ["injected_payload", "curl_unauthenticated_test", "unauthenticated_commands", "cookie_payload_base64", "exploit_request"]
            has_verified_poc = any(ind in evidence for ind in indicators)

        if has_verified_poc:
            if severity.upper() == "CRITICAL":
                return 85.0, "POC_EXISTS"
            elif severity.upper() == "HIGH":
                return 70.0, "POC_EXISTS"
            return 50.0, "POC_EXISTS"

        # Default fallback when no CVE/EPSS/PoC data exists
        return 20.0, "LOW_UNLIKELY"

    def _compute_exposure_score(self, asset: AssetContext) -> float:
        score = 0.0
        # Internet-facing is the single highest multiplier for attacker reach
        if asset.internet_facing:
            score += 65.0
        else:
            score += 25.0

        # Production vs Non-Production
        if asset.environment == "production":
            score += 35.0
        elif asset.environment == "staging":
            score += 15.0
        else:
            score += 5.0

        return min(100.0, score)

    def _compute_criticality_score(self, asset: AssetContext) -> float:
        crit_map = {"CRITICAL": 50.0, "HIGH": 40.0, "MEDIUM": 25.0, "LOW": 10.0}
        data_map = {
            "RESTRICTED_PII": 50.0,
            "CONFIDENTIAL": 35.0,
            "INTERNAL": 20.0,
            "PUBLIC": 5.0
        }
        return crit_map.get(asset.business_criticality, 25.0) + data_map.get(asset.data_classification, 20.0)

    def _evaluate_ssvc(
        self,
        exploit_state: str,
        internet_facing: bool,
        environment: str,
        composite_score: float,
        cisa_kev_listed: bool
    ) -> tuple[str, str, int]:
        """
        SSVC Decision Tree:
        - ACT: Active weaponization on exposed/production assets -> P0 (24h)
        - ATTEND: Weaponized internal or high composite risk -> P1 (72h)
        - TRACK_STAR: High theoretical impact but low weaponization -> P2 (14d)
        - TRACK: Low exploitation, internal, or routine -> P3 (30d)
        """
        is_prod = (environment == "production")

        # 1. Immediate Action required (ACT / P0)
        if (cisa_kev_listed or exploit_state == "ACTIVE_WEAPONIZED") and internet_facing and is_prod:
            return "ACT", "P0 - Immediate Action Required", 24

        if composite_score >= 82.0:
            return "ACT", "P0 - Immediate Action Required", 24

        # 2. High priority patch (ATTEND / P1)
        if (cisa_kev_listed or exploit_state in ["ACTIVE_WEAPONIZED", "HIGH_PROBABILITY"]):
            return "ATTEND", "P1 - High Priority Patch", 72

        if composite_score >= 65.0 and internet_facing:
            return "ATTEND", "P1 - High Priority Patch", 72

        # 3. Scheduled Sprint Fix (TRACK_STAR / P2)
        # Even if CVSS is 9.8, if EPSS < 0.15 and not KEV, it drops to P2!
        if composite_score >= 40.0:
            return "TRACK_STAR", "P2 - Scheduled Sprint Fix", 336  # 14 days

        # 4. Low risk / accepted (TRACK / P3)
        return "TRACK", "P3 - Informational / Risk Accepted", 720  # 30 days

    def _generate_decision_rationale(
        self,
        cvss_score: Optional[float],
        threat_intel: ThreatIntelData,
        asset_context: AssetContext,
        composite_score: float,
        priority_tier: str,
        ssvc_decision: str
    ) -> str:
        kev_txt = "Listed in CISA KEV (Actively Weaponized in the Wild)" if threat_intel.cisa_kev_listed else "Not currently recorded in CISA KEV"
        epss_txt = f"{round(threat_intel.epss_score * 100, 2)}% 30-day exploit probability" if threat_intel.epss_score is not None else "No EPSS score available"
        cvss_txt = f"CVSS {cvss_score}" if cvss_score is not None else "CVSS unrated"
        exposure_txt = "Internet-facing production asset" if (asset_context.internet_facing and asset_context.environment == 'production') else f"{asset_context.environment} asset ({'Internet-facing' if asset_context.internet_facing else 'Internal'})"

        return (
            f"Classified as {priority_tier} (SSVC: {ssvc_decision}, Score: {composite_score}/100). "
            f"Calculated from {cvss_txt}, real-world threat signals ({epss_txt}, {kev_txt}), "
            f"and asset posture on {exposure_txt}."
        )
