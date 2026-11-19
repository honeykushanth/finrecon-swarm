# agents/nodes.py
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

from langchain_core.messages import SystemMessage, HumanMessage

from state_schema import AgentState
from llm_factory import invoke_llm_with_failover
from tools.agent_tools import (
    passive_subdomain_recon,
    resolve_hosts_to_ips,
    passive_asn_lookup,
    passive_infrastructure_profile,
    enrich_and_prioritize_cves,
    load_bfsi_compliance_kb,
)

BASE_DIR = Path(__file__).resolve().parent.parent


def _extract_json_block(text: str, expect_list: bool = False) -> Any:
    """Safely extracts a JSON object or array from LLM output (strips markdown fences)."""
    cleaned = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE).replace("```", "").strip()
    start_char, end_char = ("[", "]") if expect_list else ("{", "}")
    start_idx = cleaned.find(start_char)
    end_idx = cleaned.rfind(end_char)
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        cleaned = cleaned[start_idx : end_idx + 1]
    return json.loads(cleaned)


def supervisor_node(state: AgentState) -> Dict[str, Any]:
    """
    Orchestrator Node: Evaluates global state progress, issues a tactical directive
    via the fast LLM tier, and routes to the next specialized agent with strict loop guards.
    """
    logs = list(state.get("execution_log", []))
    providers = list(state.get("llm_provider_log", []))
    errors = list(state.get("errors", []))

    done_osint = any("[OSINT]" in entry for entry in logs)
    done_infra = any("[INFRA]" in entry for entry in logs)
    done_vuln = any("[VULN]" in entry for entry in logs)
    done_report = any("[REPORT]" in entry for entry in logs)

    # Deterministic progression guard prevents infinite loops or skipped stages
    if not done_osint:
        expected_next = "osint_agent"
    elif not done_infra and state.get("resolved_ips"):
        expected_next = "infra_agent"
    elif not done_vuln and (state.get("infrastructure_map") or state.get("expired_certificates")):
        expected_next = "vuln_agent"
    elif not done_report:
        expected_next = "report_agent"
    else:
        expected_next = "FINISH"

    status_summary = {
        "target_domain": state["target_domain"],
        "completed": {
            "osint_agent": done_osint,
            "infra_agent": done_infra,
            "vuln_agent": done_vuln,
            "report_agent": done_report,
        },
        "subdomains_found": len(state.get("discovered_subdomains", [])),
        "ips_resolved": len(state.get("resolved_ips", [])),
        "hosts_profiled": len(state.get("infrastructure_map", {})),
        "compliance_findings": len(state.get("cve_findings", [])),
        "recommended_next_node": expected_next,
    }

    messages = [
        SystemMessage(
            content=(
                "You are the Supervisor Agent of FinRecon-Swarm, an ethical passive BFSI "
                "cybersecurity reconnaissance framework. Given the current workflow state, "
                "confirm the next node and write a concise 1-sentence tactical directive. "
                "Respond ONLY with valid JSON: "
                '{"next_node": "<node_name>", "directive": "<1 sentence>"}'
            )
        ),
        HumanMessage(content=json.dumps(status_summary, indent=2)),
    ]

    directive = f"Proceeding to {expected_next}."
    try:
        raw_resp, provider_used, warns = invoke_llm_with_failover(messages, tier="fast", temperature=0.0)
        providers.append(f"Supervisor -> {provider_used}")
        errors.extend(warns)
        parsed = _extract_json_block(raw_resp, expect_list=False)
        directive = parsed.get("directive", directive)
    except Exception as e:
        errors.append(f"Supervisor directive fallback: {str(e)[:120]}")

    logs.append(f"[SUPERVISOR] Next: {expected_next} | {directive}")

    return {
        "next_node": expected_next,
        "execution_log": logs,
        "llm_provider_log": providers,
        "errors": errors,
    }


def osint_agent_node(state: AgentState) -> Dict[str, Any]:
    """
    BFSI Asset & OSINT Mapper: Passively enumerates subdomains (crt.sh),
    flags expired SSL certificates, resolves IPv4 hosts, and maps target ASN.
    """
    target = state["target_domain"]
    logs = list(state.get("execution_log", []))
    errors = list(state.get("errors", []))

    # 1. Passive Certificate Transparency recon
    crt_data = json.loads(passive_subdomain_recon.invoke({"domain": target}))
    subdomains = crt_data.get("subdomains", [target])
    expired_certs = crt_data.get("expired_certificates_sample", [])
    errors.extend(crt_data.get("errors", []))

    # 2. Resilient 3-tier DNS resolution
    dns_data = json.loads(resolve_hosts_to_ips.invoke({"subdomains": subdomains}))
    resolved_ips = dns_data.get("unique_ips", [])
    errors.extend(dns_data.get("errors", []))

    # 3. Passive ASN identification on primary IP
    asn_details: Dict[str, Any] = {}
    target_asn = "Unknown"
    if resolved_ips:
        asn_details = json.loads(passive_asn_lookup.invoke({"ip_address": resolved_ips[0]}))
        target_asn = f"{asn_details.get('asn', 'Unknown')} ({asn_details.get('org_name', 'Unknown')})"

    logs.append(
        f"[OSINT] Discovered {len(subdomains)} prioritized subdomains, "
        f"{len(resolved_ips)} unique IPs, {len(expired_certs)} expired cert records, ASN: {target_asn}."
    )

    return {
        "target_asn": target_asn,
        "discovered_subdomains": subdomains,
        "resolved_ips": resolved_ips,
        "expired_certificates": expired_certs,
        "asn_details": asn_details,
        "execution_log": logs,
        "errors": errors,
    }


def infra_agent_node(state: AgentState) -> Dict[str, Any]:
    """
    Infrastructure & Service Profiler: Queries Shodan InternetDB passively
    for every resolved IP to gather open ports, CPEs, CVEs, and BFSI risk flags.
    """
    ips = state.get("resolved_ips", [])
    logs = list(state.get("execution_log", []))

    infra_map = json.loads(passive_infrastructure_profile.invoke({"ip_addresses": ips}))

    total_ports = sum(len(info.get("ports", [])) for info in infra_map.values())
    total_cves = sum(len(info.get("vulns", [])) for info in infra_map.values())
    total_alerts = sum(len(info.get("bfsi_port_alerts", [])) for info in infra_map.values())

    logs.append(
        f"[INFRA] Passively profiled {len(infra_map)} IP(s): "
        f"{total_ports} open ports, {total_cves} raw CVEs, {total_alerts} BFSI port alerts."
    )

    return {
        "infrastructure_map": infra_map,
        "execution_log": logs,
    }


def vuln_compliance_agent_node(state: AgentState) -> Dict[str, Any]:
    """
    Vulnerability & Compliance Analyst: Enriches top CVEs via CISA KEV + NVD/OSV,
    loads bfsi_compliance_kb.md, and uses the deep reasoning LLM tier to map
    technical findings directly to PCI-DSS v4.0, DORA, NYDFS Part 500, GLBA, and OWASP API.
    """
    logs = list(state.get("execution_log", []))
    providers = list(state.get("llm_provider_log", []))
    errors = list(state.get("errors", []))
    infra_map = state.get("infrastructure_map", {})

    # Aggregate raw CVEs across all profiled hosts
    all_cves: List[str] = []
    infra_highlights: Dict[str, Any] = {}
    for ip, info in infra_map.items():
        all_cves.extend(info.get("vulns", []))
        infra_highlights[ip] = {
            "hostnames": info.get("hostnames", []),
            "ports": info.get("ports", []),
            "cpes": info.get("cpes", []),
            "bfsi_port_alerts": info.get("bfsi_port_alerts", []),
            "supply_chain_cpes": info.get("supply_chain_cpes", []),
            "raw_cve_count": len(info.get("vulns", [])),
        }

    enriched_bundle: Dict[str, Any] = {
        "total_cves_received": 0,
        "cisa_kev_matches_total": 0,
        "cisa_kev_ids": [],
        "enriched_top_cves": [],
    }
    if all_cves:
        enriched_bundle = json.loads(enrich_and_prioritize_cves.invoke({"cve_ids": all_cves}))

    compliance_kb = load_bfsi_compliance_kb.invoke({})

    evidence_payload = {
        "target_domain": state["target_domain"],
        "target_asn": state.get("target_asn", "Unknown"),
        "expired_certificates_sample": state.get("expired_certificates", [])[:5],
        "infrastructure_highlights": infra_highlights,
        "cisa_kev_summary": {
            "total_unique_cves": enriched_bundle.get("total_cves_received", 0),
            "cisa_kev_matches_total": enriched_bundle.get("cisa_kev_matches_total", 0),
            "cisa_kev_ids": enriched_bundle.get("cisa_kev_ids", []),
        },
        "enriched_top_cves": enriched_bundle.get("enriched_top_cves", []),
    }

    messages = [
        SystemMessage(
            content=(
                "You are a Principal BFSI Vulnerability & Compliance Analyst. "
                "Using ONLY the evidence provided and the BFSI Compliance Knowledge Base below, "
                "produce a prioritized Compliance Risk Register as a strict JSON array.\n\n"
                "Include BOTH:\n"
                "1) Enriched CVEs (applying PCI-DSS 6.3 >30d and DORA Art. 11 ransomware/KEV modifiers)\n"
                "2) Infrastructure / Certificate findings (exposed ports like SSH/HTTP/DBs, expired certs, or 3rd-party appliances)\n\n"
                "Each JSON object MUST contain exactly these keys:\n"
                '  "finding_id" (CVE ID or concise ID like "PORT-22-SSH"),\n'
                '  "asset" (IP or subdomain),\n'
                '  "title" (short technical title),\n'
                '  "base_cvss" (score or "N/A"),\n'
                '  "adjusted_severity" ("CRITICAL", "HIGH", "MEDIUM", or "LOW"),\n'
                '  "violated_controls" (list of exact framework controls, e.g. ["PCI-DSS Req 6.3", "DORA Art. 11"]),\n'
                '  "rationale" (1-2 sentences citing evidence and severity modifier),\n'
                '  "remediation" (concrete defensive action)\n\n'
                "Respond ONLY with a valid JSON array. No extra prose.\n\n"
                f"=== BFSI COMPLIANCE KNOWLEDGE BASE ===\n{compliance_kb}"
            )
        ),
        HumanMessage(content=json.dumps(evidence_payload, indent=2)),
    ]

    findings: List[Dict[str, Any]] = []
    try:
        raw_resp, provider_used, warns = invoke_llm_with_failover(messages, tier="reasoning", temperature=0.1)
        providers.append(f"Vulnerability & Compliance Analyst -> {provider_used}")
        errors.extend(warns)
        parsed = _extract_json_block(raw_resp, expect_list=True)
        if isinstance(parsed, list):
            findings = parsed
        else:
            raise ValueError("LLM returned non-list JSON.")
    except Exception as e:
        errors.append(f"Compliance JSON parsing fallback: {str(e)[:140]}")
        findings = [
            {
                "finding_id": cve.get("cve_id", "UNKNOWN"),
                "asset": state["target_domain"],
                "title": cve.get("description", "")[:90],
                "base_cvss": str(cve.get("cvss_score", "N/A")),
                "adjusted_severity": "CRITICAL" if cve.get("in_cisa_kev") else cve.get("severity", "HIGH"),
                "violated_controls": ["PCI-DSS Req 6.3"] + (["DORA Art. 11"] if cve.get("known_ransomware_dora_11") else []),
                "rationale": "Automated fallback mapping applied from enriched NVD/CISA KEV telemetry.",
                "remediation": "Patch affected software component immediately and verify perimeter segmentation.",
            }
            for cve in enriched_bundle.get("enriched_top_cves", [])
        ]

    logs.append(
        f"[VULN] Enriched {len(enriched_bundle.get('enriched_top_cves', []))} priority CVEs "
        f"({enriched_bundle.get('cisa_kev_matches_total', 0)} CISA KEV hits) and generated "
        f"{len(findings)} BFSI compliance risk mappings."
    )

    return {
        "enriched_cves": enriched_bundle.get("enriched_top_cves", []),
        "cve_findings": findings,
        "execution_log": logs,
        "llm_provider_log": providers,
        "errors": errors,
    }


def report_synthesizer_node(state: AgentState) -> Dict[str, Any]:
    """
    Report Synthesizer Agent: Aggregates the final LangGraph state into an
    executive, CISO-ready BFSI Markdown risk report grounded in report_template.md.
    """
    logs = list(state.get("execution_log", []))
    providers = list(state.get("llm_provider_log", []))
    errors = list(state.get("errors", []))

    template_path = BASE_DIR / "report_template.md"
    report_template = (
        template_path.read_text(encoding="utf-8-sig")
        if template_path.exists()
        else "# BFSI Autonomous Risk Report"
    )
    current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Build a clean token-efficient summary of infrastructure_map (without dumping 100+ raw CVE IDs)
    compact_infra = {
        ip: {
            "hostnames": info.get("hostnames", []),
            "ports": info.get("ports", []),
            "cpes": info.get("cpes", []),
            "bfsi_port_alerts": info.get("bfsi_port_alerts", []),
            "supply_chain_cpes": info.get("supply_chain_cpes", []),
            "total_cves_detected": len(info.get("vulns", [])),
        }
        for ip, info in state.get("infrastructure_map", {}).items()
    }

    report_context = {
        "target_domain": state["target_domain"],
        "report_date": current_date,
        "target_asn": state.get("target_asn", "Unknown"),
        "asn_details": state.get("asn_details", {}),
        "discovered_subdomains": state.get("discovered_subdomains", []),
        "resolved_ips": state.get("resolved_ips", []),
        "expired_certificates_sample": state.get("expired_certificates", [])[:5],
        "infrastructure_summary": compact_infra,
        "compliance_risk_register": state.get("cve_findings", []),
        "passive_methodology_note": "100% passive reconnaissance via Certificate Transparency, DNS, BGP/ASN, Shodan InternetDB, CISA KEV, and NVD API 2.0. Zero active exploitation performed.",
    }

    messages = [
        SystemMessage(
            content=(
                "You are a Principal Cybersecurity Architect writing an executive, CISO-ready "
                "BFSI External Attack Surface & Regulatory Risk Report. Follow the exact section "
                "structure of the provided Markdown template, replacing all placeholders with rich, "
                "accurate data from the JSON telemetry.\n\n"
                "Requirements:\n"
                "- Use clean Markdown tables for Asset Inventory, Exposed Attack Surface, and the Compliance Risk Register.\n"
                "- Clearly highlight CRITICAL risks, CISA KEV hits, and specific PCI-DSS v4.0, DORA, NYDFS Part 500, GLBA, or OWASP API violations.\n"
                "- Add a concise '5. Strategic Remediation Roadmap (30/60/90-Day)' section at the end tailored for a BFSI security leadership team.\n"
                "- Never fabricate CVEs, IPs, or services not present in the JSON input.\n\n"
                f"=== REPORT TEMPLATE ===\n{report_template}"
            )
        ),
        HumanMessage(content=json.dumps(report_context, indent=2)),
    ]

    report_md, provider_used, warns = invoke_llm_with_failover(messages, tier="reasoning", temperature=0.2)
    providers.append(f"Report Synthesizer -> {provider_used}")
    errors.extend(warns)

    # Persist generated report locally in reports/
    reports_dir = BASE_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", state["target_domain"])
    output_file = reports_dir / f"{safe_name}_bfsi_report.md"
    output_file.write_text(report_md, encoding="utf-8")

    logs.append(f"[REPORT] Synthesized executive BFSI report ({len(report_md)} chars) -> saved to reports/{output_file.name}.")

    return {
        "final_markdown_report": report_md,
        "execution_log": logs,
        "llm_provider_log": providers,
        "errors": errors,
    }
