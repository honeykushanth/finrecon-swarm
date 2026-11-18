# NewZealand Project: BFSI Compliance & Risk Mapping Knowledge Base

## LLM Evaluation Instructions
You are an expert BFSI Vulnerability & Compliance Analyst. Cross-reference all incoming technical vulnerabilities (CVEs, open ports, exposed services) against the following regulatory frameworks. When a trigger condition is met, tag the vulnerability with the corresponding Regulatory Control and apply the required Severity Modifier in the final report.

---

## 1. PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
**Scope:** Any infrastructure handling, transmitting, or adjacent to credit card data or payment gateways.

*   **Requirement 2.2: System Configuration Defaults**
    *   *Trigger:* Discovery of default credentials, default vendor banners, unauthenticated administrative portals, or default installations (e.g., Apache default pages) on exposed infrastructure.
    *   *Severity Modifier:* Elevate to **HIGH**.
*   **Requirement 4.2: Protection of Data in Transit**
    *   *Trigger:* Discovery of SSL/TLS vulnerabilities (e.g., Heartbleed, POODLE, SWEET32), expired SSL certificates, untrusted self-signed certificates, or weak cipher suites (e.g., RC4, DES) on subdomains containing `pay`, `secure`, `checkout`, or `api`.
    *   *Severity Modifier:* Elevate to **CRITICAL**.
*   **Requirement 6.3: Security Vulnerability Identification**
    *   *Trigger:* Any CVE published more than 30 days ago found on internet-facing assets.
    *   *Severity Modifier:* Standard CVSS score applies.
*   **Requirement 11.2: External Network Vulnerability Scans**
    *   *Trigger:* Discovery of exposed internal databases (e.g., MongoDB, Redis, PostgreSQL, MySQL) accessible from the public internet without network segmentation.
    *   *Severity Modifier:* Elevate to **CRITICAL**.

## 2. DORA (Digital Operational Resilience Act - EU)
**Scope:** Protection against systemic banking failures, third-party vendor risks, and widespread outages.

*   **Article 9: Protection and Prevention**
    *   *Trigger:* Vulnerabilities related to resource exhaustion, memory leaks, or Denial of Service (DoS/DDoS) that could take a financial portal offline.
    *   *Severity Modifier:* Elevate to **HIGH**.
*   **Article 11: Response and Recovery**
    *   *Trigger:* Exposed backup servers (e.g., open Rsync ports 873, exposed FTP/SFTP with backup extensions), or vulnerabilities with known ransomware exploitation chains (e.g., SMB/RDP flaws like BlueKeep, EternalBlue).
    *   *Severity Modifier:* Elevate to **CRITICAL**.
*   **Article 28: ICT Third-Party Risk Management**
    *   *Trigger:* Vulnerabilities discovered in third-party enterprise vendor appliances (e.g., Citrix Gateways, Fortinet/Pulse Secure VPNs, Cisco ASA routers, F5 BIG-IP).
    *   *Severity Modifier:* Tag as **SUPPLY CHAIN RISK**.

## 3. NYDFS 23 NYCRR Part 500 (New York Department of Financial Services)
**Scope:** Baseline cybersecurity requirements for financial services companies.

*   **Section 500.12: Multi-Factor Authentication (MFA)**
    *   *Trigger:* Exposed Remote Desktop Protocol (RDP - Port 3389), Secure Shell (SSH - Port 22), or enterprise VPN portals lacking explicit MFA enforcement indicators.
    *   *Severity Modifier:* Elevate to **CRITICAL**.
*   **Section 500.15: Encryption of Nonpublic Information (NPI)**
    *   *Trigger:* Data transmission over unencrypted plaintext protocols (e.g., HTTP over Port 80 without redirection, Telnet Port 23, FTP Port 21) exposing potential login forms or APIs.
    *   *Severity Modifier:* Elevate to **HIGH**.

## 4. GLBA (Gramm-Leach-Bliley Act - Safeguards Rule)
**Scope:** US financial institutions protecting consumer financial privacy.

*   **Access Controls & Authentication**
    *   *Trigger:* Information disclosure vulnerabilities (e.g., exposed `.git` directories, `.env` files, open directory listings) that could leak consumer PII or backend credentials.
    *   *Severity Modifier:* Elevate to **HIGH**.

## 5. Open Banking & API Risk (OWASP API Top 10)
**Scope:** Financial APIs facilitating open banking data exchanges (e.g., Plaid integrations, mobile banking APIs).

*   **API1:2023 - Broken Object Level Authorization (BOLA)**
    *   *Trigger:* Unauthenticated API endpoints exposing excessive data blocks or lacking rate-limiting (HTTP 429 absence) discovered during passive enumeration.
    *   *Severity Modifier:* Elevate to **HIGH**.
*   **API7:2023 - Server Side Request Forgery (SSRF)**
    *   *Trigger:* Outdated web-application frameworks vulnerable to SSRF, allowing external actors to pivot into the internal banking network.
    *   *Severity Modifier:* Elevate to **CRITICAL**.