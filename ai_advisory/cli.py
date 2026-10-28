from __future__ import annotations
import sys
import json
import argparse
from pathlib import Path

# Fix Windows console UTF-8 encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from .pipeline import AIAdvisoryPipeline


def format_table_row(cols: list[str], widths: list[int]) -> str:
    return " | ".join(f"{c:<{w}}" for c, w in zip(cols, widths))


def run_cli() -> None:
    parser = argparse.ArgumentParser(
        description="🛡️ AI Advisory: Live Threat Intel (EPSS/KEV) & Deterministic Risk Prioritization CLI"
    )
    parser.add_argument(
        "--file", "-f",
        type=str,
        default=None,
        help="Path to JSON findings file (defaults to ai_advisory/data/sample_findings.json)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Path to export structured JSON advisory report"
    )
    parser.add_argument(
        "--cve",
        type=str,
        default=None,
        help="Quick threat intel check for a single CVE ID"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print full executive AI narratives for each finding"
    )

    args = parser.parse_args()

    pipeline = AIAdvisoryPipeline()

    # Mode 1: Quick single CVE lookup
    if args.cve:
        cve_id = args.cve.strip().upper()
        print(f"\n🔍 Querying Threat Intelligence for {cve_id}...")
        intel = pipeline.intel.get_intel_for_cve(cve_id)
        epss_str = f"{round((intel.epss_score or 0.0) * 100, 2)}%" if intel.epss_score is not None else "N/A"
        pct_str = f"{round((intel.epss_percentile or 0.0) * 100, 1)}%" if intel.epss_percentile is not None else "N/A"
        kev_str = "🚨 YES (Active In-The-Wild Exploitation)" if intel.cisa_kev_listed else "NO (Not cataloged)"
        print("\n" + "=" * 65)
        print(f"CVE ID:            {intel.cve_id}")
        print(f"EPSS Probability:  {epss_str} (Percentile: {pct_str})")
        print(f"CISA KEV Listed:   {kev_str}")
        if intel.cisa_vulnerability_name:
            print(f"KEV Vulnerability: {intel.cisa_vulnerability_name}")
            print(f"CISA Date Added:   {intel.cisa_date_added} | Remediation Due: {intel.cisa_due_date}")
        print(f"Ransomware Use:    {'KNOWN' if intel.known_ransomware_campaign else 'Not recorded'}")
        print(f"Data Source:       {intel.intel_source} [{intel.query_status}]")
        print("=" * 65 + "\n")
        return

    # Mode 2: Batch Findings Triage
    target_file = args.file
    if not target_file:
        default_sample = Path(__file__).resolve().parent / "data" / "sample_findings.json"
        if default_sample.exists():
            target_file = str(default_sample)
        else:
            sec_sample = Path(__file__).resolve().parent.parent / "Security" / "data" / "findings.json"
            target_file = str(sec_sample)

    print(f"\n================================================================================")
    print(f"🛡️  AI ADVISORY: LIVE THREAT INTEL & RISK PRIORITIZATION ENGINE")
    print(f"================================================================================")
    print(f"[*] Ingesting findings from: {target_file}")
    print(f"[*] Querying FIRST.org EPSS and CISA KEV feeds...")
    print(f"[*] Applying deterministic SSVC matrix and generating AI advisory narratives...\n")

    batch_report = pipeline.process_batch(target_file)

    # Print Summary Metrics
    print(f"┌{'─'*78}┐")
    print(f"│ BATCH TRIAGE METRICS SUMMARY{' '*49}│")
    print(f"├{'─'*78}┤")
    print(f"│ Total Analyzed Findings: {batch_report.total_findings:<10}  CISA KEV Weaponized: {batch_report.cisa_kev_active_count:<10}│")
    print(f"│ P0 Immediate Action:     {batch_report.p0_immediate_count:<10}  P1 High Priority:    {batch_report.p1_high_count:<10}│")
    print(f"│ P2 Scheduled Sprint:     {batch_report.p2_medium_count:<10}  P3 Informational:    {batch_report.p3_low_count:<10}│")
    print(f"└{'─'*78}┘\n")

    # Comparative Table: The "CVSS Lie" Buster Table
    headers = ["ID", "CVE ID", "CVSS", "EPSS %", "CISA KEV", "SSVC", "Calculated Priority", "SLA"]
    widths = [9, 14, 6, 8, 10, 10, 28, 6]

    print(format_table_row(headers, widths))
    print("-" * (sum(widths) + len(widths) * 3 - 3))

    for item in batch_report.findings:
        cve = item.cve_id or "Custom"
        cvss = f"{item.cvss_score:.1f}" if item.cvss_score is not None else "N/A"
        epss = f"{item.threat_intel.epss_score * 100:.1f}%" if item.threat_intel.epss_score is not None else "N/A"
        kev = "🚨 YES" if item.threat_intel.cisa_kev_listed else "NO"
        ssvc = item.prioritization.ssvc_decision
        prio = item.prioritization.priority_tier.split(" - ")[0] + " (" + f"{item.prioritization.composite_risk_score:.0f}/100)"
        sla = f"{item.prioritization.remediation_sla_hours}h"

        row = [item.finding_id, cve, cvss, epss, kev, ssvc, prio, sla]
        print(format_table_row(row, widths))

    print("\n" + "=" * 80)

    # Verbose Narratives
    if args.verbose or True:  # Default display sample narrative
        print("\n📢 EXECUTIVE ADVISORY NARRATIVE HIGHLIGHTS:")
        print("=" * 80)
        for i, item in enumerate(batch_report.findings[:3], 1):
            if item.narrative:
                print(f"\n[{i}] {item.finding_id}: {item.title}")
                print(f"    Assigned Priority: {item.prioritization.priority_tier} (SLA: {item.prioritization.remediation_sla_hours}h)")
                print(f"    Executive Headline: {item.narrative.executive_headline}")
                print(f"    Exploitability Assessment: {item.narrative.exploitability_assessment}")
                print(f"    Action Plan: {item.narrative.action_recommendation}")
                print("-" * 80)

    # Export if requested
    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(batch_report.model_dump_json(indent=2))
        print(f"\n[✓] Structured JSON Advisory Report exported to: {out_p}")


if __name__ == "__main__":
    run_cli()
