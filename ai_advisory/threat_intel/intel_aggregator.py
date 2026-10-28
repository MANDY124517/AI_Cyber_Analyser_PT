from __future__ import annotations
from typing import Optional
from ..models import ThreatIntelData
from .epss_client import EPSSClient
from .cisa_kev_client import CISAKEVClient


class ThreatIntelAggregator:
    """Aggregates multiple authoritative vulnerability intelligence feeds (EPSS + CISA KEV)."""

    def __init__(self, epss_client: Optional[EPSSClient] = None, kev_client: Optional[CISAKEVClient] = None):
        self.epss = epss_client or EPSSClient()
        self.kev = kev_client or CISAKEVClient()

    def get_intel_for_cve(self, cve_id: Optional[str]) -> ThreatIntelData:
        """Fetch threat intelligence for a given CVE ID."""
        if not cve_id or not str(cve_id).strip():
            return ThreatIntelData(
                cve_id=None,
                epss_score=None,
                epss_percentile=None,
                cisa_kev_listed=False,
                query_status="NOT_APPLICABLE",
                intel_source="No CVE Provided"
            )

        clean_cve = str(cve_id).strip().upper()
        epss_res = self.epss.get_score(clean_cve)
        kev_res = self.kev.check_vulnerability(clean_cve)

        status = "LIVE_API"
        if epss_res.get("status") == "OFFLINE_CACHE" or kev_res.get("query_status") == "OFFLINE_CACHE":
            status = "OFFLINE_CACHE"
        elif epss_res.get("status") == "API_ERROR":
            status = "API_ERROR"

        return ThreatIntelData(
            cve_id=clean_cve,
            epss_score=epss_res.get("epss"),
            epss_percentile=epss_res.get("percentile"),
            cisa_kev_listed=kev_res.get("listed", False),
            cisa_date_added=kev_res.get("date_added"),
            cisa_due_date=kev_res.get("due_date"),
            cisa_vulnerability_name=kev_res.get("vulnerability_name"),
            known_ransomware_campaign=kev_res.get("known_ransomware_campaign", False),
            intel_source="FIRST.org EPSS + CISA KEV",
            query_status=status
        )
