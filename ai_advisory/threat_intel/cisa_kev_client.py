from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger("ai_advisory.cisa_kev")

# Curated fallback for primary weaponized vulnerabilities in case network is down
OFFLINE_KEV_FALLBACK: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2022-22965": {
        "vulnerabilityName": "Spring Framework Remote Code Execution Vulnerability (Spring4Shell)",
        "dateAdded": "2022-04-04",
        "dueDate": "2022-04-25",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2021-26855": {
        "vulnerabilityName": "Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon)",
        "dateAdded": "2021-11-03",
        "dueDate": "2021-11-17",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2018-13379": {
        "vulnerabilityName": "Fortinet FortiOS SSL-VPN Path Traversal",
        "dateAdded": "2021-11-03",
        "dueDate": "2021-11-17",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2020-5902": {
        "vulnerabilityName": "F5 BIG-IP Traffic Management User Interface (TMUI) Remote Code Execution",
        "dateAdded": "2021-11-03",
        "dueDate": "2021-11-17",
        "knownRansomwareCampaignUse": "Known"
    },
    "CVE-2023-38606": {
        "vulnerabilityName": "Apple Multiple Products Memory Corruption Vulnerability",
        "dateAdded": "2023-07-26",
        "dueDate": "2023-08-16",
        "knownRansomwareCampaignUse": "Unknown"
    },
    "CVE-2023-4863": {
        "vulnerabilityName": "Google Chromium WebP Heap Buffer Overflow",
        "dateAdded": "2023-09-13",
        "dueDate": "2023-10-04",
        "knownRansomwareCampaignUse": "Unknown"
    }
}


class CISAKEVClient:
    """Client for querying the CISA Known Exploited Vulnerabilities (KEV) Catalog."""

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, cache_dir: Optional[Path] = None, timeout: float = 8.0):
        self.timeout = timeout
        if cache_dir is None:
            cache_dir = Path(__file__).resolve().parent.parent / "data"
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.catalog_file = self.cache_dir / "cisa_kev_catalog.json"
        self._kev_index: Dict[str, Dict[str, Any]] = {}
        self._initialize_catalog()

    def _initialize_catalog(self) -> None:
        """Load catalog from local disk or fetch if absent/empty."""
        if self.catalog_file.exists():
            try:
                with open(self.catalog_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        self._index_vulnerabilities(vulns)
                        logger.info(f"Loaded {len(self._kev_index)} KEV entries from local cache.")
                        return
            except Exception as e:
                logger.warning(f"Failed to read local KEV cache: {e}")

        # Fetch live catalog
        self.refresh_catalog()

    def refresh_catalog(self) -> bool:
        """Fetch fresh copy of CISA KEV catalog over HTTPS."""
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(self.FEED_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        self._index_vulnerabilities(vulns)
                        with open(self.catalog_file, "w", encoding="utf-8") as f:
                            json.dump(data, f)
                        logger.info(f"Fetched and indexed {len(self._kev_index)} live CISA KEV entries.")
                        return True
        except Exception as e:
            logger.debug(f"Failed to fetch live CISA KEV: {e}")

        # Seed with fallback if index is still empty
        if not self._kev_index:
            self._kev_index = dict(OFFLINE_KEV_FALLBACK)
            logger.info("Initialized KEV with curated fallback catalog.")
        return False

    def _index_vulnerabilities(self, vulns: list) -> None:
        index: Dict[str, Dict[str, Any]] = {}
        for item in vulns:
            cve = item.get("cveID", "").strip().upper()
            if cve:
                index[cve] = item
        self._kev_index = index

    def check_vulnerability(self, cve_id: str) -> Dict[str, Any]:
        """Check if CVE ID is listed in CISA KEV catalog."""
        cve = cve_id.strip().upper()
        if not cve.startswith("CVE-"):
            return {
                "listed": False,
                "vulnerability_name": None,
                "date_added": None,
                "due_date": None,
                "known_ransomware_campaign": False,
                "query_status": "NOT_APPLICABLE"
            }

        # Check in indexed catalog
        if cve in self._kev_index:
            entry = self._kev_index[cve]
            ransomware = str(entry.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
            return {
                "listed": True,
                "vulnerability_name": entry.get("vulnerabilityName"),
                "date_added": entry.get("dateAdded"),
                "due_date": entry.get("dueDate"),
                "known_ransomware_campaign": ransomware,
                "query_status": "LIVE_API" if self.catalog_file.exists() else "OFFLINE_CACHE"
            }

        # Not listed in KEV
        return {
            "listed": False,
            "vulnerability_name": None,
            "date_added": None,
            "due_date": None,
            "known_ransomware_campaign": False,
            "query_status": "LIVE_API"
        }
