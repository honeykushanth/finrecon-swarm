# tools/agent_tools.py
import json
from pathlib import Path
from typing import List
from langchain_core.tools import tool

from tools.osint_tools import (
    enumerate_subdomains_crtsh,
    resolve_subdomains_to_ips,
    lookup_asn_info,
)
from tools.infra_tools import profile_ip_internetdb, profile_multiple_ips
from tools.vuln_tools import prioritize_and_enrich_cves

BASE_DIR = Path(__file__).resolve().parent.parent


@tool
def passive_subdomain_recon(domain: str) -> str:
    """
    Passively discovers BFSI-prioritized subdomains and expired SSL/TLS certificates
    for a target root domain using Certificate Transparency logs (crt.sh).
    Input: root domain string (e.g., 'example.com').
    """
    data = enumerate_subdomains_crtsh(domain, max_results=20)
    return json.dumps(data, indent=2)


@tool
def resolve_hosts_to_ips(subdomains: List[str]) -> str:
    """
    Resolves a list of subdomains to IPv4 addresses using a resilient 3-tier resolver
    (dnspython -> OS socket -> Google DNS-over-HTTPS).
    Input: list of subdomain strings.
    """
    data = resolve_subdomains_to_ips(subdomains)
    return json.dumps(data, indent=2)


@tool
def passive_asn_lookup(ip_address: str) -> str:
    """
    Passively retrieves Autonomous System Number (ASN) and network owner details
    for an IPv4 address using BGPView with ipinfo.io failover.
    Input: IPv4 address string (e.g., '45.33.32.156').
    """
    data = lookup_asn_info(ip_address)
    return json.dumps(data, indent=2)


@tool
def passive_infrastructure_profile(ip_addresses: List[str]) -> str:
    """
    Passively profiles up to 10 IPv4 addresses via Shodan InternetDB to identify
    open ports, software CPEs, known CVEs, BFSI port risks, and DORA third-party vendors.
    Input: list of IPv4 address strings.
    """
    data = profile_multiple_ips(ip_addresses, max_ips=10)
    return json.dumps(data, indent=2)


@tool
def enrich_and_prioritize_cves(cve_ids: List[str]) -> str:
    """
    Cross-references a list of CVE IDs against CISA KEV (actively exploited / ransomware)
    and enriches the top priority CVEs via NVD API 2.0 (with OSV fallback) including
    CVSS scores and PCI-DSS Req 6.3 (>30 days old) flags.
    Input: list of CVE ID strings (e.g., ['CVE-2021-44790', 'CVE-2023-25690']).
    """
    data = prioritize_and_enrich_cves(cve_ids, max_enrich=5)
    return json.dumps(data, indent=2)


@tool
def load_bfsi_compliance_kb() -> str:
    """
    Loads the authoritative BFSI Compliance & Risk Mapping Knowledge Base
    (PCI-DSS v4.0, DORA, NYDFS Part 500, GLBA, OWASP API Top 10) for regulatory mapping.
    """
    kb_path = BASE_DIR / "bfsi_compliance_kb.md"
    if not kb_path.exists():
        return "ERROR: bfsi_compliance_kb.md not found in project root."
    return kb_path.read_text(encoding="utf-8-sig")


# Grouped toolkits ready to bind to each LangGraph agent in Phase 4
OSINT_AGENT_TOOLS = [passive_subdomain_recon, resolve_hosts_to_ips, passive_asn_lookup]
INFRA_AGENT_TOOLS = [passive_infrastructure_profile]
VULN_AGENT_TOOLS = [enrich_and_prioritize_cves, load_bfsi_compliance_kb]
