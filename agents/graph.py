# agents/graph.py
from typing import Dict, Any, Generator
from langgraph.graph import StateGraph, END

from state_schema import AgentState
from agents.nodes import (
    supervisor_node,
    osint_agent_node,
    infra_agent_node,
    vuln_compliance_agent_node,
    report_synthesizer_node,
)


def _route_from_supervisor(state: AgentState) -> str:
    return state.get("next_node", "FINISH")


def build_finrecon_graph():
    """Compiles the stateful LangGraph multi-agent BFSI reconnaissance swarm."""
    workflow = StateGraph(AgentState)

    # Register nodes
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("osint_agent", osint_agent_node)
    workflow.add_node("infra_agent", infra_agent_node)
    workflow.add_node("vuln_agent", vuln_compliance_agent_node)
    workflow.add_node("report_agent", report_synthesizer_node)

    # Entry point
    workflow.set_entry_point("supervisor")

    # Conditional routing controlled by the Supervisor
    workflow.add_conditional_edges(
        "supervisor",
        _route_from_supervisor,
        {
            "osint_agent": "osint_agent",
            "infra_agent": "infra_agent",
            "vuln_agent": "vuln_agent",
            "report_agent": "report_agent",
            "FINISH": END,
        },
    )

    # Every worker node reports back to the Supervisor
    workflow.add_edge("osint_agent", "supervisor")
    workflow.add_edge("infra_agent", "supervisor")
    workflow.add_edge("vuln_agent", "supervisor")
    workflow.add_edge("report_agent", "supervisor")

    return workflow.compile()


def create_initial_state(target_domain: str) -> AgentState:
    clean_domain = (
        target_domain.strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )
    return {
        "target_domain": clean_domain,
        "target_asn": "Unknown",
        "discovered_subdomains": [],
        "resolved_ips": [],
        "expired_certificates": [],
        "asn_details": {},
        "infrastructure_map": {},
        "enriched_cves": [],
        "cve_findings": [],
        "final_markdown_report": "",
        "next_node": "osint_agent",
        "execution_log": [],
        "llm_provider_log": [],
        "errors": [],
    }


def stream_finrecon_swarm(target_domain: str) -> Generator[Dict[str, Any], None, None]:
    """Yields node-by-node state updates for real-time Streamlit UI streaming."""
    app = build_finrecon_graph()
    initial_state = create_initial_state(target_domain)
    for event in app.stream(initial_state, config={"recursion_limit": 20}):
        yield event


def run_finrecon_swarm(target_domain: str) -> AgentState:
    """Runs the complete autonomous swarm end-to-end and returns final AgentState."""
    app = build_finrecon_graph()
    initial_state = create_initial_state(target_domain)
    return app.invoke(initial_state, config={"recursion_limit": 20})


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"\n=== Launching FinRecon-Swarm (Passive BFSI Recon) on: {target} ===\n")
    final_state = run_finrecon_swarm(target)

    print("--- EXECUTION TRACE ---")
    for line in final_state.get("execution_log", []):
        print(" ", line)

    print("\n--- LLM PROVIDERS USED ---")
    for line in final_state.get("llm_provider_log", []):
        print(" ", line)

    if final_state.get("errors"):
        print("\n--- WARNINGS / ERRORS ---")
        for err in final_state["errors"]:
            print(" ", err)

    print("\n--- REPORT PREVIEW (First 1,200 chars) ---")
    print(final_state.get("final_markdown_report", "")[:1200])
