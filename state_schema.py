# state_schema.py
from typing import TypedDict, List, Dict, Any


class AgentState(TypedDict):
    """
    The global state dictionary shared across all LangGraph nodes.
    """
    target_domain: str
    target_asn: str

    # OSINT Mapper Data
    discovered_subdomains: List[str]
    resolved_ips: List[str]
    expired_certificates: List[Dict[str, Any]]
    asn_details: Dict[str, Any]

    # Infrastructure Profiler Data (IP -> ports, CPEs, CVEs, BFSI port alerts, supply chain CPEs)
    infrastructure_map: Dict[str, Dict[str, Any]]

    # Vulnerability & Compliance Analyst Data
    enriched_cves: List[Dict[str, Any]]
    cve_findings: List[Dict[str, Any]]

    # Final Report Output
    final_markdown_report: str

    # Orchestration, Observability & Failover Tracking
    next_node: str
    execution_log: List[str]
    llm_provider_log: List[str]
    errors: List[str]
