# app.py
import os
import re
import pandas as pd
import streamlit as st

from agents.graph import stream_finrecon_swarm
from utils.pdf_exporter import markdown_to_pdf_bytes

st.set_page_config(
    page_title="FinRecon-Swarm | BFSI Agentic Cyber Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Subtle executive styling
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.5rem; }
    .stMetric { background-color: rgba(30, 41, 59, 0.35); border: 1px solid rgba(148, 163, 184, 0.25); padding: 0.75rem; border-radius: 0.6rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Sidebar Configuration ---
with st.sidebar:
    st.title("🛡️ FinRecon-Swarm")
    st.caption("Autonomous Passive BFSI Reconnaissance & Compliance Framework")
    st.divider()

    st.subheader("🎯 Target Selection")
    preset = st.selectbox(
        "Authorized Test Targets",
        options=["Custom Domain...", "scanme.nmap.org", "example.com"],
        index=1,
    )
    default_domain = "" if preset == "Custom Domain..." else preset
    target_input = st.text_input(
        "Target Root Domain",
        value=default_domain,
        placeholder="e.g., scanme.nmap.org",
    )

    ethical_confirm = st.checkbox(
        "I confirm this target is authorized for 100% passive OSINT & compliance analysis.",
        value=True,
    )

    launch_btn = st.button(
        "🚀 Launch Agent Swarm",
        type="primary",
        use_container_width=True,
        disabled=not (ethical_confirm and target_input.strip()),
    )

    st.divider()
    st.subheader("⚙️ Active Architecture")
    st.markdown(
        """
        - **Orchestrator:** LangGraph StateGraph
        - **Fast Tier:** Groq `gpt-oss-20b`
        - **Reasoning Tier:** Groq `gpt-oss-120b`
        - **Local Failover:** Ollama `llama3.1`
        - **Passive Sources:** `crt.sh`, DNS/DoH, BGPView/ipinfo, Shodan InternetDB, CISA KEV, NVD API 2.0
        - **Compliance KB:** PCI-DSS v4.0, DORA, NYDFS 500, GLBA, OWASP API
        """
    )

# --- Header ---
st.title("FinRecon-Swarm: BFSI Agentic Cybersecurity Command Center")
st.info(
    "**Ethical Guardrail Active:** All agents operate in **100% passive mode** (Certificate Transparency logs, "
    "DNS/ASN intelligence, Shodan InternetDB, CISA KEV, and NVD 2.0). Zero active exploitation or intrusive probing is performed."
)

if "final_state" not in st.session_state:
    st.session_state.final_state = None

# --- Live Swarm Execution ---
if launch_btn:
    clean_target = target_input.strip().lower()
    merged_state = {"target_domain": clean_target}

    node_labels = {
        "supervisor": "🧠 Supervisor Agent routing next phase...",
        "osint_agent": "🔍 BFSI Asset & OSINT Mapper querying crt.sh, DNS & ASN...",
        "infra_agent": "🛰️ Infrastructure Profiler querying Shodan InternetDB...",
        "vuln_agent": "⚖️ Vulnerability & Compliance Analyst correlating CISA KEV, NVD & BFSI KB...",
        "report_agent": "📄 Report Synthesizer drafting CISO-ready BFSI Risk Report...",
    }

    with st.status(f"Executing FinRecon-Swarm on `{clean_target}`...", expanded=True) as status:
        try:
            for event in stream_finrecon_swarm(clean_target):
                for node_name, node_update in event.items():
                    merged_state.update(node_update)
                    st.write(f"**{node_labels.get(node_name, node_name)}**")
                    latest_logs = node_update.get("execution_log", [])
                    if latest_logs:
                        st.caption(latest_logs[-1])

            status.update(label=f"✅ Swarm assessment complete for `{clean_target}`!", state="complete", expanded=False)
            st.session_state.final_state = merged_state
        except Exception as e:
            status.update(label="❌ Swarm execution encountered an error", state="error")
            st.error(f"Execution failed: {str(e)}")

# --- Results Dashboard ---
state = st.session_state.final_state

if state:
    target_domain = state.get("target_domain", "target")
    subdomains = state.get("discovered_subdomains", [])
    resolved_ips = state.get("resolved_ips", [])
    infra_map = state.get("infrastructure_map", {})
    findings = state.get("cve_findings", [])
    enriched_cves = state.get("enriched_cves", [])
    report_md = state.get("final_markdown_report", "")

    total_ports = sum(len(v.get("ports", [])) for v in infra_map.values())
    kev_hits = sum(1 for c in enriched_cves if c.get("in_cisa_kev"))
    critical_count = sum(1 for f in findings if str(f.get("adjusted_severity", "")).upper() == "CRITICAL")

    # Top KPI Row
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Prioritized Subdomains", len(subdomains))
    c2.metric("Resolved IPs", len(resolved_ips))
    c3.metric("Exposed Ports", total_ports)
    c4.metric("CISA KEV Hits", kev_hits)
    c5.metric("Critical Findings", critical_count)

    st.divider()

    tab_report, tab_risk, tab_assets, tab_telemetry = st.tabs([
        "📄 Executive Report & Export",
        "⚖️ Compliance Risk Register",
        "🛰️ Attack Surface & Assets",
        "🔧 Swarm Telemetry & Failover",
    ])

    # Tab 1: Executive Report + Downloads
    with tab_report:
        safe_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", target_domain)
        dl1, dl2, _ = st.columns([1, 1, 2])

        with dl1:
            st.download_button(
                label="⬇️ Download Markdown (.md)",
                data=report_md.encode("utf-8"),
                file_name=f"{safe_slug}_bfsi_report.md",
                mime="text/markdown",
                use_container_width=True,
            )

        with dl2:
            pdf_bytes = markdown_to_pdf_bytes(report_md, target_domain=target_domain)
            st.download_button(
                label="📑 Download Executive PDF (.pdf)",
                data=pdf_bytes,
                file_name=f"{safe_slug}_bfsi_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        st.divider()
        st.markdown(report_md)

    # Tab 2: Interactive Compliance Risk Register
    with tab_risk:
        st.subheader("Prioritized BFSI Regulatory Risk Register")
        if findings:
            rows = []
            for f in findings:
                controls = f.get("violated_controls", [])
                if isinstance(controls, list):
                    controls = ", ".join(controls)
                rows.append({
                    "Finding ID": f.get("finding_id", "N/A"),
                    "Asset": f.get("asset", target_domain),
                    "Severity": str(f.get("adjusted_severity", "UNKNOWN")).upper(),
                    "Base CVSS": str(f.get("base_cvss", "N/A")),
                    "CISA KEV": "YES" if f.get("in_cisa_kev") else "No",
                    "Regulatory Controls": controls,
                    "Title": f.get("title", ""),
                    "Remediation": f.get("remediation", ""),
                })
            df_risk = pd.DataFrame(rows)

            sev_filter = st.multiselect(
                "Filter by Adjusted Severity",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            )
            filtered_df = df_risk[df_risk["Severity"].isin(sev_filter)] if sev_filter else df_risk
            st.dataframe(filtered_df, use_container_width=True, hide_index=True)
        else:
            st.info("No compliance findings generated for this target.")

    # Tab 3: Attack Surface & Asset Inventory
    with tab_assets:
        col_a, col_b = st.columns(2)
        with col_a:
            st.subheader("ASN & Network Ownership")
            st.json(state.get("asn_details", {}))
            st.subheader("Discovered Subdomains (BFSI Prioritized)")
            st.write(subdomains)
        with col_b:
            st.subheader("Passive Infrastructure Telemetry (InternetDB)")
            for ip, info in infra_map.items():
                with st.expander(f"IP: {ip} — {len(info.get('ports', []))} Ports | {len(info.get('vulns', []))} Raw CVEs", expanded=True):
                    st.write("**Hostnames:**", info.get("hostnames", []))
                    st.write("**Open Ports:**", info.get("ports", []))
                    st.write("**CPEs:**", info.get("cpes", []))
                    if info.get("bfsi_port_alerts"):
                        st.warning("**BFSI Port Alerts:**\n- " + "\n- ".join(info["bfsi_port_alerts"]))
                    if info.get("supply_chain_cpes"):
                        st.error("**DORA Art. 28 Third-Party Appliances:** " + ", ".join(info["supply_chain_cpes"]))

    # Tab 4: Execution Trace & Failover Audit
    with tab_telemetry:
        st.subheader("Agent Execution Trace")
        for line in state.get("execution_log", []):
            st.code(line, language="text")

        st.subheader("LLM Provider & Failover Audit Log")
        for line in state.get("llm_provider_log", []):
            st.success(line) if "Groq" in line else st.warning(line)

        if state.get("errors"):
            st.subheader("Warnings / Non-Fatal Errors")
            for err in state["errors"]:
                st.warning(err)
        else:
            st.success("Zero errors or fallbacks triggered during this run.")
else:
    st.markdown(
        """
        ### Ready to Start
        1. Select an authorized test domain in the left sidebar (e.g., `scanme.nmap.org`).
        2. Click **🚀 Launch Agent Swarm** to watch the 5-agent LangGraph pipeline run live.
        3. Inspect the Compliance Risk Register and export your CISO-ready **PDF** or **Markdown** report.
        """
    )
