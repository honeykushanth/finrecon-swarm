# tools/infra_tools.py
from typing import Dict, List, Any
import requests

HEADERS = {"User-Agent": "FinRecon-Swarm/1.0 (Academic-Passive-OSINT)"}

BFSI_SENSITIVE_PORTS = {
    21: "FTP (Plaintext / Backup Exposure - NYDFS 500.15, DORA Art. 11)",
    22: "SSH (Admin Access - Verify MFA under NYDFS 500.12)",
    23: "Telnet (Unencrypted Admin Protocol - NYDFS 500.15)",
    80: "HTTP (Verify Strict HTTPS Redirect - NYDFS 500.15)",
    445: "SMB (High Ransomware Risk - DORA Art. 11)",
    873: "Rsync (Potential Exposed Backup Server - DORA Art. 11)",
    1433: "MSSQL (Exposed Internal Database - PCI-DSS Req 11.2)",
    3306: "MySQL (Exposed Internal Database - PCI-DSS Req 11.2)",
    3389: "RDP (High Ransomware & MFA Risk - NYDFS 500.12, DORA Art. 11)",
    5432: "PostgreSQL (Exposed Internal Database - PCI-DSS Req 11.2)",
    6379: "Redis (Exposed Internal Database - PCI-DSS Req 11.2)",
    27017: "MongoDB (Exposed Internal Database - PCI-DSS Req 11.2)",
}

THIRD_PARTY_APPLIANCE_VENDORS = (
    "citrix", "fortinet", "cisco", "f5", "paloaltonetworks",
    "pulse_secure", "ivanti", "juniper", "checkpoint"
)


def profile_ip_internetdb(ip: str) -> Dict[str, Any]:
    """
    Passively profiles an IP address via Shodan InternetDB without touching the target.
    Enriches raw output with BFSI port risk flags and DORA third-party vendor flags.
    """
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code == 404:
            return {
                "ip": ip,
                "ports": [],
                "cpes": [],
                "vulns": [],
                "hostnames": [],
                "tags": [],
                "bfsi_port_alerts": [],
                "supply_chain_cpes": [],
                "status": "No passive records found in InternetDB"
            }
        resp.raise_for_status()
        data = resp.json()

        ports = data.get("ports", [])
        cpes = data.get("cpes", [])

        bfsi_port_alerts = [
            f"Port {p}: {BFSI_SENSITIVE_PORTS[p]}"
            for p in ports if p in BFSI_SENSITIVE_PORTS
        ]

        supply_chain_cpes = [
            cpe for cpe in cpes
            if any(vendor in cpe.lower() for vendor in THIRD_PARTY_APPLIANCE_VENDORS)
        ]

        return {
            "ip": ip,
            "ports": ports,
            "cpes": cpes,
            "vulns": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "bfsi_port_alerts": bfsi_port_alerts,
            "supply_chain_cpes": supply_chain_cpes,
            "status": "Success"
        }

    except Exception as e:
        return {
            "ip": ip,
            "ports": [],
            "cpes": [],
            "vulns": [],
            "hostnames": [],
            "tags": [],
            "bfsi_port_alerts": [],
            "supply_chain_cpes": [],
            "status": f"Error: {str(e)}"
        }


def profile_multiple_ips(ips: List[str], max_ips: int = 10) -> Dict[str, Dict[str, Any]]:
    """
    Profiles up to `max_ips` passively via InternetDB and returns a dictionary
    matching AgentState['infrastructure_map'].
    """
    results: Dict[str, Dict[str, Any]] = {}
    for ip in ips[:max_ips]:
        results[ip] = profile_ip_internetdb(ip)
    return results
