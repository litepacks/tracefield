# Security & Responsible Disclosure Statement

## 1. Purpose & Intended Use
`tracefield` is a **defensive web application security middleware and probe detector** designed exclusively for:
- Protecting web applications from automated scanner reconnaissance and bot probes.
- Safeguarding sensitive application routes (such as `.env`, `.git/config`, `wp-config.php`) through intelligent detection, blocking, and honeypot deception.
- Forensic log analysis and defensive threat intelligence.

This tool is strictly non-offensive:
- It **never** scans, attacks, floods, or interacts aggressively with external hosts or networks.
- It operates solely as an incoming HTTP middleware within the developer's own web server or edge worker.

---

## 2. Safety & Privacy Constraints
- **Zero Secret Exposure**: `tracefield` never reads or serves real application secrets, local `.env` files, or host credentials. All generated payloads are 100% synthetic and randomized.
- **Safe Fake Namespaces**: All decoy endpoints and generated data strictly use:
  - Private RFC 1918 addresses (`10.x.x.x`).
  - Reserved IANA/RFC testing TLDs (`.test`, `.invalid`, `example.com`).
  - Clearly identifiable fake key markers (e.g. `tracefield_fake_...`, `tracefield_decoy_...`).
- **Privacy Compliance**: Client IP addresses are anonymized by default (`/24` for IPv4 and `/48` for IPv6) in compliance with GDPR and privacy standards.
- **No Resource Exhaustion**: Middleware responses are lightweight and stream-safe, avoiding any slow-loris or resource exhaustion side-effects.

---

## 3. Vulnerability Reporting & Contact
If you discover a potential vulnerability or security flaw in `tracefield`, we appreciate your help in disclosing it responsibly.

Please report vulnerabilities privately via:
- GitHub Security Advisories, or
- Directly contacting the project maintainers.

We are committed to addressing verified security issues promptly.
