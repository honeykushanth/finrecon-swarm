# tools/osint_tools.py
from datetime import datetime, timezone
from typing import Dict, List, Any
import socket
import requests
import dns.resolver

HEADERS = {"User-Agent": "FinRecon-Swarm/1.0 (Academic-Passive-OSINT)"}

BFSI_PRIORITY_KEYWORDS = (
    "pay", "payment", "bank", "portal", "secure", "api", "gw", "gateway",
    "auth", "login", "sso", "vpn", "admin", "card", "swift", "vault",
    "checkout", "mobile", "openbanking", "db", "backup", "citrix"
)


def enumerate_subdomains_crtsh(domain: str, max_results: int = 25) -> Dict[str, Any]:
    """
    Passively enumerates subdomains and flags expired certificates via crt.sh
    Certificate Transparency logs. Sends zero packets to the target.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    expired_certs = []
    errors = []

    try:
        resp = requests.get(url, headers=HEADERS, timeout=25)
        resp.raise_for_status()
        records = resp.json()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

        for entry in records:
            name_value = entry.get("name_value", "")
            not_after = entry.get("not_after", "")
            is_expired = False

            if not_after:
                try:
                    exp_dt = datetime.strptime(not_after[:19], "%Y-%m-%dT%H:%M:%S")
                    is_expired = exp_dt < now_utc
                except ValueError:
                    pass

            for raw_name in name_value.splitlines():
                clean_name = raw_name.strip().lower().lstrip("*.")
                if clean_name and clean_name.endswith(domain.lower()):
                    subdomains.add(clean_name)
                    if is_expired and len(expired_certs) < 10:
                        expired_certs.append({
                            "subdomain": clean_name,
                            "expired_on": not_after[:10],
                            "issuer": entry.get("issuer_name", "Unknown")[:80]
                        })

    except Exception as e:
        errors.append(f"crt.sh lookup failed for {domain}: {str(e)}")

    # Always include root domain as a baseline
    subdomains.add(domain.lower())

    # Prioritize BFSI high-value subdomains first
    def bfsi_priority(sub: str) -> tuple:
        has_kw = any(kw in sub for kw in BFSI_PRIORITY_KEYWORDS)
        return (0 if has_kw else 1, len(sub), sub)

    sorted_subs = sorted(subdomains, key=bfsi_priority)[:max_results]

    return {
        "domain": domain,
        "subdomains": sorted_subs,
        "total_discovered": len(subdomains),
        "expired_certificates_sample": expired_certs,
        "errors": errors
    }


def _resolve_via_doh(domain: str) -> List[str]:
    """DNS-over-HTTPS fallback over Port 443 for networks blocking UDP/53."""
    try:
        resp = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "A"},
            headers=HEADERS,
            timeout=5
        )
        if resp.status_code == 200:
            answers = resp.json().get("Answer", [])
            return [a["data"] for a in answers if a.get("type") == 1 and "data" in a]
    except Exception:
        pass
    return []


def resolve_subdomains_to_ips(subdomains: List[str]) -> Dict[str, Any]:
    """
    Resilient 3-tier IPv4 resolver:
    1) dnspython -> 2) OS socket resolver -> 3) DNS-over-HTTPS (Google DoH).
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    mapping: Dict[str, List[str]] = {}
    unique_ips = set()
    errors = []

    for sub in subdomains:
        ips: List[str] = []

        # Tier 1: dnspython
        try:
            answers = resolver.resolve(sub, "A")
            ips = [rdata.address for rdata in answers]
        except Exception as e1:
            # Tier 2: OS socket fallback
            try:
                infos = socket.getaddrinfo(sub, None, socket.AF_INET)
                ips = sorted({info[4][0] for info in infos})
            except Exception as e2:
                # Tier 3: DNS-over-HTTPS (Port 443)
                ips = _resolve_via_doh(sub)
                if not ips:
                    errors.append(f"{sub}: dnspython({type(e1).__name__}), socket({type(e2).__name__}), DoH(empty)")

        if ips:
            mapping[sub] = ips
            unique_ips.update(ips)

    return {
        "subdomain_ip_map": mapping,
        "unique_ips": sorted(unique_ips),
        "errors": errors
    }


def lookup_asn_info(ip: str) -> Dict[str, Any]:
    """
    Passively retrieves ASN and network ownership details via BGPView,
    with automatic failover to ipinfo.io if BGPView is rate-limited.
    """
    # Primary: BGPView API
    try:
        resp = requests.get(f"https://api.bgpview.io/ip/{ip}", headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            prefixes = data.get("prefixes", [])
            if prefixes:
                asn_obj = prefixes[0].get("asn", {})
                return {
                    "ip": ip,
                    "asn": f"AS{asn_obj.get('asn', 'Unknown')}",
                    "org_name": asn_obj.get("description") or asn_obj.get("name", "Unknown"),
                    "prefix": prefixes[0].get("prefix", "Unknown"),
                    "country": asn_obj.get("country_code", "Unknown"),
                    "source": "BGPView"
                }
    except Exception:
        pass

    # Fallback: ipinfo.io (Free public tier, no key needed)
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            org_field = data.get("org", "Unknown")
            parts = org_field.split(" ", 1)
            return {
                "ip": ip,
                "asn": parts[0] if parts[0].startswith("AS") else "Unknown",
                "org_name": parts[1] if len(parts) > 1 else org_field,
                "prefix": "N/A",
                "country": data.get("country", "Unknown"),
                "source": "ipinfo.io (Fallback)"
            }
    except Exception as e:
        return {"ip": ip, "asn": "Unknown", "org_name": "Unknown", "error": str(e)}

    return {"ip": ip, "asn": "Unknown", "org_name": "Unknown", "source": "None"}
