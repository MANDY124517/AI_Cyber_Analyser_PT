from __future__ import annotations
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from ..models import (
    ThreatIntelData,
    AssetContext,
    PrioritizationResult,
    AdvisoryNarrative,
)
from .prompts import NARRATIVE_SYSTEM_PROMPT, build_narrative_user_prompt

logger = logging.getLogger("ai_advisory.narrative")


class NarrativeGenerator:
    """
    Generates grounded Prioritization Narratives explaining deterministic triage
    scores to leadership. Supports live LLMs (Gemini/OpenAI/Claude/Ollama) with
    an expert deterministic heuristic fallback.
    """

    def __init__(self, env_path: Optional[Path] = None):
        self._ollama_healthy: Optional[bool] = None
        self._openai_healthy: Optional[bool] = None
        self._gemini_healthy: Optional[bool] = None
        self._load_environment(env_path)

    def _load_environment(self, env_path: Optional[Path] = None) -> None:
        """Attempt to load API keys and endpoints from .env files."""
        candidates = [
            env_path,
            Path(__file__).resolve().parent.parent.parent / "Security" / ".env",
            Path(__file__).resolve().parent.parent.parent / ".env",
        ]
        for p in candidates:
            if p and p.exists():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                k, v = line.split("=", 1)
                                k, v = k.strip(), v.strip()
                                if k and k not in os.environ:
                                    os.environ[k] = v
                except Exception as e:
                    logger.debug(f"Could not load {p}: {e}")

    def generate(
        self,
        finding_title: str,
        category: str,
        severity: str,
        cve_id: Optional[str],
        cvss_score: Optional[float],
        asset: str,
        threat_intel: ThreatIntelData,
        asset_context: AssetContext,
        prioritization: PrioritizationResult,
    ) -> AdvisoryNarrative:
        """Generate structured advisory narrative."""
        user_prompt = build_narrative_user_prompt(
            title=finding_title,
            cve_id=cve_id,
            cvss=cvss_score,
            severity=severity,
            asset=asset,
            priority_tier=prioritization.priority_tier,
            composite_score=prioritization.composite_risk_score,
            ssvc_decision=prioritization.ssvc_decision,
            sla_hours=prioritization.remediation_sla_hours,
            epss_score=threat_intel.epss_score,
            epss_percentile=threat_intel.epss_percentile,
            cisa_kev=threat_intel.cisa_kev_listed,
            known_ransomware=threat_intel.known_ransomware_campaign,
            internet_facing=asset_context.internet_facing,
            environment=asset_context.environment,
            business_criticality=asset_context.business_criticality
        )

        # 1. Try Live LLM generation if configured
        llm_response = self._try_llm_generation(user_prompt)
        if llm_response:
            try:
                data = json.loads(llm_response)
                return AdvisoryNarrative(**data)
            except Exception as e:
                logger.debug(f"Failed to parse LLM narrative JSON: {e}")

        # 2. Expert Heuristic Fallback (Grounded, deterministic, 100% offline-ready)
        return self._generate_expert_heuristic(
            finding_title=finding_title,
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            asset=asset,
            threat_intel=threat_intel,
            asset_context=asset_context,
            prioritization=prioritization
        )

    def _try_llm_generation(self, user_prompt: str) -> Optional[str]:
        """Query LLM if credentials or local instance are available."""
        # Check OpenAI
        if self._openai_healthy is not False:
            openai_key = os.getenv("OPENAI_API_KEY")
            if openai_key and len(openai_key) > 5:
                try:
                    import httpx
                    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
                    headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
                    body = {
                        "model": model,
                        "messages": [
                            {"role": "system", "content": NARRATIVE_SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt}
                        ],
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"}
                    }
                    with httpx.Client(timeout=10.0) as client:
                        res = client.post("https://api.openai.com/v1/chat/completions", json=body, headers=headers)
                        if res.status_code == 200:
                            self._openai_healthy = True
                            return res.json()["choices"][0]["message"]["content"]
                        else:
                            self._openai_healthy = False
                except Exception as e:
                    self._openai_healthy = False
                    logger.debug(f"OpenAI narrative call failed: {e}")
            else:
                self._openai_healthy = False

        # Check Gemini
        if self._gemini_healthy is not False:
            gemini_key = os.getenv("GEMINI_API_KEY")
            if gemini_key and len(gemini_key) > 5:
                try:
                    import httpx
                    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
                    body = {
                        "contents": [{"parts": [{"text": f"{NARRATIVE_SYSTEM_PROMPT}\n\n{user_prompt}"}]}],
                        "generationConfig": {"temperature": 0.2, "response_mime_type": "application/json"}
                    }
                    with httpx.Client(timeout=10.0) as client:
                        res = client.post(url, json=body)
                        if res.status_code == 200:
                            self._gemini_healthy = True
                            return res.json()["candidates"][0]["content"]["parts"][0]["text"]
                        else:
                            self._gemini_healthy = False
                except Exception as e:
                    self._gemini_healthy = False
                    logger.debug(f"Gemini narrative call failed: {e}")
            else:
                self._gemini_healthy = False

        # Check Ollama
        if self._ollama_healthy is not False:
            if os.getenv("USE_OLLAMA", "").lower() in ["true", "1"]:
                try:
                    import httpx
                    host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
                    model = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
                    body = {
                        "model": model,
                        "prompt": f"{NARRATIVE_SYSTEM_PROMPT}\n\n{user_prompt}",
                        "stream": False,
                        "format": "json"
                    }
                    with httpx.Client(timeout=1.5) as client:
                        res = client.post(f"{host}/api/generate", json=body)
                        if res.status_code == 200:
                            self._ollama_healthy = True
                            return res.json().get("response")
                        else:
                            self._ollama_healthy = False
                except Exception as e:
                    self._ollama_healthy = False
                    logger.debug(f"Ollama narrative call failed: {e}")
            else:
                self._ollama_healthy = False

        return None

    def _generate_expert_heuristic(
        self,
        finding_title: str,
        cve_id: Optional[str],
        cvss_score: Optional[float],
        severity: str,
        asset: str,
        threat_intel: ThreatIntelData,
        asset_context: AssetContext,
        prioritization: PrioritizationResult,
    ) -> AdvisoryNarrative:
        """Deterministic, battle-tested cyber analyst narrative template."""
        is_p0 = "P0" in prioritization.priority_tier
        is_p1 = "P1" in prioritization.priority_tier
        is_p2 = "P2" in prioritization.priority_tier

        # 1. Headline
        if is_p0:
            headline = f"CRITICAL THREAT: {finding_title} on {asset} is actively weaponized and requires emergency mitigation."
        elif is_p1:
            headline = f"HIGH PRIORITY: Elevated exploitation risk detected for {finding_title}; prioritized for 72-hour remediation."
        elif is_p2:
            headline = f"SCHEDULED TRIAGE: {finding_title} carries moderate real-world threat; routed to standard sprint backlog."
        else:
            headline = f"LOW RISK / MONITORED: Minimal real-world exploitation observed for {finding_title}."

        # 2. Prioritization Justification
        epss_desc = f"{round((threat_intel.epss_score or 0.0) * 100, 2)}% 30-day exploit probability" if threat_intel.epss_score is not None else "No EPSS data"
        kev_desc = "actively weaponized in the wild according to CISA KEV" if threat_intel.cisa_kev_listed else "not cataloged on CISA KEV"
        justification = (
            f"The engine classified this finding as {prioritization.priority_tier} (Score: {prioritization.composite_risk_score}/100, SSVC: {prioritization.ssvc_decision}). "
            f"While theoretical CVSS is {cvss_score or 'unrated'}, empirical threat intelligence registers an EPSS of {epss_desc} and is {kev_desc}. "
            f"Combined with asset deployment in {asset_context.environment.upper()} ({'Internet-facing' if asset_context.internet_facing else 'Internal network'}), "
            f"this justifies an operational SLA of {prioritization.remediation_sla_hours} hours."
        )

        # 3. Exploitability Assessment
        if threat_intel.cisa_kev_listed:
            exploit_text = (
                f"Empirical confirmation: This vulnerability ({cve_id or 'flaw'}) has crossed the threshold from theoretical risk to proven attacker weaponization. "
                f"CISA has mandated remediation due to observed exploitation campaigns. High urgency applies regardless of lower CVSS sub-components."
            )
        elif threat_intel.epss_score and threat_intel.epss_score >= 0.50:
            exploit_text = (
                f"High weaponization probability: With an EPSS probability of {round(threat_intel.epss_score * 100, 1)}% (top {round((1.0 - (threat_intel.epss_percentile or 0.9)) * 100, 1)}% of all CVEs), "
                f"functional exploits or active scanning activity indicate imminent in-the-wild exploitation."
            )
        elif threat_intel.epss_score and threat_intel.epss_score < 0.15 and (cvss_score or 0) >= 7.0:
            exploit_text = (
                f"The 'CVSS Inflation Trap': Although carrying an elevated CVSS score of {cvss_score}, the EPSS exploit prediction is very low ({round(threat_intel.epss_score * 100, 2)}%) "
                f"with zero confirmed CISA KEV entries. In accordance with platform design principles, this finding is de-escalated to avoid engineering alert fatigue."
            )
        else:
            exploit_text = (
                f"Verified detection: The issue represents confirmed technical risk ({severity}) with concrete telemetry evidence, "
                f"evaluated under standard operational conditions."
            )

        # 4. Asset Exposure Context
        exposure_text = (
            f"Asset '{asset}' is situated in the {asset_context.environment} tier with public internet reachability: "
            f"{'EXPOSED TO ADVERSARIES' if asset_context.internet_facing else 'PROTECTED BEHIND PERIMETER'}. "
            f"Business criticality is flagged as {asset_context.business_criticality} handling {asset_context.data_classification.replace('_', ' ')} data."
        )

        # 5. Action Recommendation
        if is_p0:
            action = f"EMERGENCY PROTOCOL: Invoke P0 incident workflow. Apply containment rule/WAF block within 4 hours; deploy permanent patch within {prioritization.remediation_sla_hours} hours."
        elif is_p1:
            action = f"ACCELERATED FIX: Assign directly to owning engineering squad. Implement fix within the {prioritization.remediation_sla_hours}-hour SLA."
        elif is_p2:
            action = f"SPRINT BACKLOG: Track under SSVC '{prioritization.ssvc_decision}'. Address during the next standard 14-day release cycle."
        else:
            action = "MONITOR & ACCEPT: Retain under periodic re-scanning. No immediate out-of-band developer interruption required."

        return AdvisoryNarrative(
            executive_headline=headline,
            prioritization_justification=justification,
            exploitability_assessment=exploit_text,
            asset_exposure_context=exposure_text,
            action_recommendation=action
        )
