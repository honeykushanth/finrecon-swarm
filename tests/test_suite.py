# tests/test_suite.py
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure project root is importable when running directly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from langchain_core.messages import SystemMessage, HumanMessage
from tools.osint_tools import resolve_subdomains_to_ips, lookup_asn_info
from tools.infra_tools import profile_ip_internetdb
from tools.vuln_tools import prioritize_and_enrich_cves
from tools.agent_tools import load_bfsi_compliance_kb
from llm_factory import invoke_llm_with_failover
from utils.pdf_exporter import markdown_to_pdf_bytes


class TestFinReconSwarm(unittest.TestCase):
    """End-to-end unit, compliance, failover, and reporting verification suite."""

    def test_01_compliance_kb_integrity(self):
        """Verify all 5 BFSI regulatory frameworks exist in bfsi_compliance_kb.md."""
        kb = load_bfsi_compliance_kb.invoke({})
        for framework in ("PCI-DSS", "DORA", "NYDFS", "GLBA", "OWASP API"):
            self.assertIn(framework, kb, f"Missing framework in KB: {framework}")

    def test_02_passive_dns_and_asn(self):
        """Verify resilient DNS resolution and ASN lookup on authorized sandbox."""
        dns_res = resolve_subdomains_to_ips(["scanme.nmap.org"])
        self.assertIn("45.33.32.156", dns_res["unique_ips"])

        asn_res = lookup_asn_info("45.33.32.156")
        self.assertTrue(asn_res.get("asn", "").startswith("AS"))
        self.assertNotEqual(asn_res.get("org_name"), "Unknown")

    def test_03_passive_internetdb_bfsi_alerts(self):
        """Verify Shodan InternetDB passive profiling triggers NYDFS port alerts."""
        infra = profile_ip_internetdb("45.33.32.156")
        self.assertEqual(infra["status"], "Success")
        self.assertTrue(len(infra["ports"]) > 0)
        alerts_blob = " ".join(infra["bfsi_port_alerts"])
        self.assertIn("NYDFS", alerts_blob)

    def test_04_cisa_kev_and_nvd_enrichment(self):
        """Verify CVE-2021-40438 triggers CISA KEV, DORA Art. 11 ransomware, and PCI-DSS 6.3."""
        res = prioritize_and_enrich_cves(["CVE-2021-40438"], max_enrich=1)
        self.assertEqual(res["cisa_kev_matches_total"], 1)
        top = res["enriched_top_cves"][0]
        self.assertEqual(top["cve_id"], "CVE-2021-40438")
        self.assertTrue(top["in_cisa_kev"])
        self.assertTrue(top["known_ransomware_dora_11"])
        self.assertTrue(top["older_than_30_days_pci_6_3"])

    def test_05_groq_to_ollama_local_failover(self):
        """Simulate Groq key/quota failure and verify automatic failover to local Ollama llama3.1."""
        msgs = [
            SystemMessage(content="You are a cybersecurity test agent."),
            HumanMessage(content="Reply with the single word: FAILOVER_OK"),
        ]
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_my_key"}):
            text, provider, warns = invoke_llm_with_failover(msgs, tier="fast", temperature=0.0)
        self.assertIn("Ollama", provider)
        self.assertTrue(len(warns) > 0)
        self.assertTrue(len(text.strip()) > 0)

    def test_06_pdf_exporter_sanitization(self):
        """Verify PDF exporter generates a valid PDF binary and handles wide tables & <br> tags."""
        sample_md = (
            "# BFSI Test Report\n\n"
            "## 1. Executive Summary\nTest summary with smart dash \u2014 and bullet.\n\n"
            "| Finding | Asset | Severity | KEV | Controls | Action |\n"
            "|---|---|---|---|---|---|\n"
            "| CVE-2021-40438 | 45.33.32.156 | CRITICAL | Yes | PCI-DSS 6.3<br>DORA Art. 11 | Patch Apache |\n"
        )
        pdf_bytes = markdown_to_pdf_bytes(sample_md, target_domain="scanme.nmap.org")
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 1500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
