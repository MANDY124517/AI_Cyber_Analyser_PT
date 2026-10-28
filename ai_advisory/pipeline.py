from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Union, Optional

from .models import (
    AssetContext,
    ThreatIntelData,
    PrioritizationResult,
    AdvisoryFindingReport,
    AdvisoryBatchReport,
)
from .threat_intel.intel_aggregator import ThreatIntelAggregator
from .prioritization.matrix import PrioritizationEngine
from .narrative.generator import NarrativeGenerator

logger = logging.getLogger("ai_advisory.pipeline")


class AIAdvisoryPipeline:
    """
    End-to-end AI Advisory Pipeline for Threat Intel Enrichment and
    Deterministic Risk Prioritization.
    """

    def __init__(
        self,
        intel_aggregator: Optional[ThreatIntelAggregator] = None,
        prioritization_engine: Optional[PrioritizationEngine] = None,
        narrative_generator: Optional[NarrativeGenerator] = None,
    ):
        self.intel = intel_aggregator or ThreatIntelAggregator()
        self.prioritization = prioritization_engine or PrioritizationEngine()
        self.narrative = narrative_generator or NarrativeGenerator()

    def process_finding(
        self,
        finding_data: Dict[str, Any],
        asset_override: Optional[AssetContext] = None
    ) -> AdvisoryFindingReport:
        """Process a single finding through intel enrichment, deterministic scoring, and advisory narrative."""
        finding_id = finding_data.get("id", "SEC-UNKNOWN")
        title = finding_data.get("title", "Untitled Vulnerability")
        category = finding_data.get("category", "General Security")
        severity = finding_data.get("severity", "MEDIUM")
        cve_id = finding_data.get("cve_id")
        cvss_score = finding_data.get("cvss_score")
        asset_name = finding_data.get("asset", "unknown-asset")
        evidence = finding_data.get("evidence", {})
        metadata = finding_data.get("metadata", {})

        # 1. Resolve Asset Context
        if asset_override:
            asset_ctx = asset_override
        else:
            env = metadata.get("environment", "production").lower()
            # Infer internet facing from asset name / tags
            tags = [t.lower() for t in metadata.get("tags", [])]
            is_internet = True
            if "internal" in asset_name.lower() or "internal" in tags:
                is_internet = False
            elif any(domain in asset_name.lower() for domain in [".internal", ".corp", ".local"]):
                is_internet = False

            asset_ctx = AssetContext(
                asset_id=asset_name,
                environment=env if env in ["production", "staging", "development"] else "production",
                internet_facing=is_internet,
                business_criticality="CRITICAL" if "critical-infrastructure" in tags else "HIGH",
                data_classification="RESTRICTED_PII" if ("pii-leak" in tags or "gdpr-risk" in tags) else "CONFIDENTIAL"
            )

        # 2. Enrich with Threat Intelligence (EPSS + CISA KEV)
        threat_intel = self.intel.get_intel_for_cve(cve_id)

        # 3. Deterministic Prioritization Scoring
        prioritization = self.prioritization.calculate_priority(
            cvss_score=cvss_score,
            severity=severity,
            threat_intel=threat_intel,
            asset_context=asset_ctx,
            evidence=evidence
        )

        # 4. Generate AI Advisory Narrative
        advisory_narrative = self.narrative.generate(
            finding_title=title,
            category=category,
            severity=severity,
            cve_id=cve_id,
            cvss_score=cvss_score,
            asset=asset_name,
            threat_intel=threat_intel,
            asset_context=asset_ctx,
            prioritization=prioritization
        )

        return AdvisoryFindingReport(
            finding_id=finding_id,
            title=title,
            category=category,
            severity=severity,
            cve_id=cve_id,
            cvss_score=cvss_score,
            asset=asset_name,
            threat_intel=threat_intel,
            asset_context=asset_ctx,
            prioritization=prioritization,
            narrative=advisory_narrative
        )

    def process_batch(
        self,
        findings: Union[List[Dict[str, Any]], str, Path]
    ) -> AdvisoryBatchReport:
        """Process a collection or JSON file of findings."""
        if isinstance(findings, (str, Path)):
            p = Path(findings)
            with open(p, "r", encoding="utf-8") as f:
                raw_items = json.load(f)
        else:
            raw_items = findings

        reports: List[AdvisoryFindingReport] = []
        p0_count = p1_count = p2_count = p3_count = 0
        kev_count = high_epss_count = 0

        for item in raw_items:
            report = self.process_finding(item)
            reports.append(report)

            if "P0" in report.prioritization.priority_tier:
                p0_count += 1
            elif "P1" in report.prioritization.priority_tier:
                p1_count += 1
            elif "P2" in report.prioritization.priority_tier:
                p2_count += 1
            else:
                p3_count += 1

            if report.threat_intel.cisa_kev_listed:
                kev_count += 1
            if report.threat_intel.epss_score and report.threat_intel.epss_score >= 0.50:
                high_epss_count += 1

        return AdvisoryBatchReport(
            total_findings=len(reports),
            p0_immediate_count=p0_count,
            p1_high_count=p1_count,
            p2_medium_count=p2_count,
            p3_low_count=p3_count,
            cisa_kev_active_count=kev_count,
            high_epss_count=high_epss_count,
            findings=reports
        )
