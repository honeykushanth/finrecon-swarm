# tools/vuln_tools.py
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import time
import requests

HEADERS = {"User-Agent": "FinRecon-Swarm/1.0 (Academic-Passive-OSINT)"}
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_URL = "https://api.osv.dev/v1/vulns"

# In-memory cache so we only fetch the CISA KEV catalog once per run
_KEV_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def load_cisa_kev_catalog() -> Dict[str, Dict[str, Any]]:
    """
    Fetches and caches CISA's Known Exploited Vulnerabilities (KEV) catalog.
    100% free, no API key required. Maps CVE ID -> exploitation & ransomware metadata.
    """
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE

    kev_map: Dict[str, Dict[str, Any]] = {}
    try:
        resp = requests.get(CISA_KEV_URL, headers=HEADERS, timeout=15)
        resp.raise_for_status()
        for item in resp.json().get("vulnerabilities", []):
            cve_id = item.get("cveID")
            if cve_id:
                kev_map[cve_id] = {
                    "vendor_project": item.get("vendorProject", "Unknown"),
                    "product": item.get("product", "Unknown"),
                    "vulnerability_name": item.get("vulnerabilityName", ""),
                    "date_added": item.get("dateAdded", ""),
                    "known_ransomware": item.get("knownRansomwareCampaignUse", "Unknown")
                }
        _KEV_CACHE = kev_map
    except Exception:
        _KEV_CACHE = {}

    return _KEV_CACHE


def _lookup_cve_osv(cve_id: str) -> Optional[Dict[str, Any]]:
    """Fallback CVE lookup via OSV.dev (free, high rate limit)."""
    try:
        resp = requests.get(f"{OSV_API_URL}/{cve_id}", headers=HEADERS, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            published = data.get("published", "")[:10]
            summary = data.get("summary") or data.get("details", "No description available.")
            return {
                "cve_id": cve_id,
                "cvss_score": "N/A",
                "severity": "UNKNOWN",
                "published_date": published,
                "description": summary[:280],
                "source": "OSV.dev (Fallback)"
            }
    except Exception:
        pass
    return None


def lookup_cve_details(cve_id: str) -> Dict[str, Any]:
    """
    Queries NVD API 2.0 for CVSS score, severity, published date, and description.
    Automatically checks PCI-DSS Req 6.3 (>30 days old) and CISA KEV status,
    with fallback to OSV.dev if NVD is rate-limited.
    """
    kev_catalog = load_cisa_kev_catalog()
    kev_hit = kev_catalog.get(cve_id)

    result: Dict[str, Any] = {
        "cve_id": cve_id,
        "cvss_score": "N/A",
        "severity": "UNKNOWN",
        "published_date": "Unknown",
        "older_than_30_days_pci_6_3": False,
        "in_cisa_kev": bool(kev_hit),
        "known_ransomware_dora_11": (
            kev_hit.get("known_ransomware") == "Known" if kev_hit else False
        ),
        "description": "Details unavailable.",
        "source": "None"
    }

    # Primary: NVD API 2.0
    try:
        resp = requests.get(NVD_API_URL, params={"cveId": cve_id}, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                cve_obj = vulns[0].get("cve", {})
                published = cve_obj.get("published", "")[:10]

                # Extract English description
                descriptions = cve_obj.get("descriptions", [])
                desc_text = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                    "No English description."
                )

                # Extract highest available CVSS metric (v3.1 -> v3.0 -> v2)
                metrics = cve_obj.get("metrics", {})
                cvss_score = "N/A"
                severity = "UNKNOWN"

                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        metric_entry = metrics[key][0]
                        cvss_data = metric_entry.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", "N/A")
                        severity = (
                            cvss_data.get("baseSeverity")
                            or metric_entry.get("baseSeverity")
                            or "UNKNOWN"
                        )
                        break

                result.update({
                    "cvss_score": cvss_score,
                    "severity": str(severity).upper(),
                    "published_date": published,
                    "description": desc_text[:280],
                    "source": "NVD API 2.0"
                })
    except Exception:
        pass

    # Fallback: OSV.dev if NVD returned nothing or throttled
    if result["source"] == "None":
        osv_data = _lookup_cve_osv(cve_id)
        if osv_data:
            result.update(osv_data)

    # Calculate PCI-DSS Req 6.3 (>30 days since publication)
    if result["published_date"] and result["published_date"] != "Unknown":
        try:
            pub_dt = datetime.strptime(result["published_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - pub_dt).days
            result["older_than_30_days_pci_6_3"] = age_days > 30
        except ValueError:
            pass

    return result


def prioritize_and_enrich_cves(cve_list: List[str], max_enrich: int = 5) -> Dict[str, Any]:
    """
    Deduplicates and prioritizes CVEs by:
      1) Presence in CISA KEV (actively exploited in the wild)
      2) Newest CVE year first
    Enriches the top `max_enrich` CVEs to protect free-tier NVD and Groq token budgets.
    """
    unique_cves = list(dict.fromkeys(cve_list))
    kev_catalog = load_cisa_kev_catalog()

    def sort_key(cve_id: str) -> tuple:
        in_kev = 0 if cve_id in kev_catalog else 1
        try:
            parts = cve_id.split("-")
            year = -int(parts[1])
            num = -int(parts[2])
        except Exception:
            year, num = 0, 0
        return (in_kev, year, num)

    prioritized = sorted(unique_cves, key=sort_key)
    selected = prioritized[:max_enrich]

    enriched: List[Dict[str, Any]] = []
    for idx, cve_id in enumerate(selected):
        enriched.append(lookup_cve_details(cve_id))
        # Respect NVD public rate limit cleanly between calls
        if idx < len(selected) - 1:
            time.sleep(0.7)

    kev_matches = [c for c in unique_cves if c in kev_catalog]

    return {
        "total_cves_received": len(unique_cves),
        "cisa_kev_matches_total": len(kev_matches),
        "cisa_kev_ids": kev_matches[:15],
        "enriched_top_cves": enriched
    }
