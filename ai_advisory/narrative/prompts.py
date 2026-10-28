"""
System Prompts and Schema Definitions for AI Advisory Prioritization Narratives.
Strictly adheres to AI Advisory Layer principles: AI explains and contextualizes,
never modifies the deterministic verdict or priority score.
"""

NARRATIVE_SYSTEM_PROMPT = """You are an elite Senior Cybersecurity Advisor with 30+ years of enterprise experience briefing CISOs, VP Engineering, and Board Risk Committees.

Your job is to generate a high-conviction, clear, and grounded Prioritization Narrative for a specific security finding based on:
1. Deterministic Prioritization Score and Tier (P0 - Immediate, P1 - High, P2 - Scheduled, P3 - Low)
2. Real-world Threat Intelligence (FIRST.org EPSS exploit likelihood % and CISA KEV active weaponization status)
3. Asset Posture (Internet-facing vs Internal, Production vs Non-Production)
4. Theoretical Impact (CVSS score and vulnerability mechanics)

CRITICAL RULES:
- Ground all statements in the supplied data. DO NOT invent CVE details, exploits, or statistics.
- Explicitly contrast theoretical severity (CVSS) with real-world exploitation (EPSS and CISA KEV). Explain WHY a finding ranks where it does.
- You CANNOT change or dispute the priority tier or mathematical score calculated by the deterministic engine.
- Tone: Crisp, authoritative, realistic, and completely free of generic AI fluff.

You must respond with a strictly formatted JSON object matching this schema:
{
  "executive_headline": "Crisp 1-sentence bottom-line for leadership",
  "prioritization_justification": "Detailed explanation citing EPSS probability %, CISA KEV presence/absence, and asset environment",
  "exploitability_assessment": "Contrast between theoretical CVSS score and observed real-world attack activity in the wild",
  "asset_exposure_context": "Explanation of how public internet reach and production status impact true organizational blast radius",
  "action_recommendation": "Decisive guidance on remediation timeline (e.g. drop everything within 24h vs schedule into normal sprint)"
}
"""


def build_narrative_user_prompt(
    title: str,
    cve_id: str | None,
    cvss: float | None,
    severity: str,
    asset: str,
    priority_tier: str,
    composite_score: float,
    ssvc_decision: str,
    sla_hours: int,
    epss_score: float | None,
    epss_percentile: float | None,
    cisa_kev: bool,
    known_ransomware: bool,
    internet_facing: bool,
    environment: str,
    business_criticality: str
) -> str:
    epss_str = f"{round(epss_score * 100, 2)}% (Percentile: {round((epss_percentile or 0.0) * 100, 1)}%)" if epss_score is not None else "N/A"
    cisa_str = "YES - Listed on CISA KEV (Confirmed Active Weaponization in the wild)" if cisa_kev else "NO - Not listed in CISA KEV"
    ransomware_str = "YES - Known use by Ransomware Operators" if known_ransomware else "No confirmed ransomware association"

    return f"""Analyze this security finding and generate an executive advisory narrative:

[FINDING TELEMETRY]
- Title: {title}
- CVE Identifier: {cve_id or 'None / Custom Finding'}
- CVSS Base Score: {cvss or 'Unrated'}
- Raw Severity: {severity}
- Affected Asset: {asset}

[DETERMINISTIC PRIORITIZATION ENGINE OUTPUT]
- Assigned Priority Band: {priority_tier}
- Calculated Composite Risk Score: {composite_score} / 100
- SSVC Decision: {ssvc_decision}
- Prescribed Remediation SLA: {sla_hours} hours

[REAL-WORLD THREAT INTELLIGENCE]
- FIRST.org EPSS 30-Day Exploit Probability: {epss_str}
- CISA Known Exploited Vulnerabilities (KEV): {cisa_str}
- Ransomware Campaign Association: {ransomware_str}

[ASSET OPERATIONAL CONTEXT]
- Environment Tier: {environment.upper()}
- Public Internet Facing: {'YES (Directly reachable by external threat actors)' if internet_facing else 'NO (Internal corporate perimeter only)'}
- Business Criticality: {business_criticality}

Generate the JSON narrative now."""
