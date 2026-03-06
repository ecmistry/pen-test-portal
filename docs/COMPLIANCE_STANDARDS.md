# Ghoststrike — Compliance Standards & Frameworks

This document lists the security standards, compliance frameworks, and industry methodologies that Ghoststrike aligns with. It is intended for auditors, stakeholders, and clients who need evidence of what the platform covers.

---

## 1. Frameworks & Standards

### OWASP Top 10:2021

**What it is:** The OWASP Top 10 is the industry-standard awareness document for web application security, maintained by the Open Web Application Security Project. It represents the most critical security risks to web applications.

**How Ghoststrike aligns:**

- Every finding is mapped to an OWASP Top 10 category where applicable.
- Reports include an OWASP coverage summary.

| OWASP Category | Description | Ghoststrike Coverage |
|----------------|-------------|----------------------|
| A01:2021 | Broken Access Control | Directory traversal, HTTP method checks, sensitive path exposure, CSRF detection, mass assignment testing, authenticated multi-role vertical/horizontal escalation, IDOR detection, URL normalisation bypass (percent-encoding, dot-segments, double-slashes, host header manipulation), secret/credential exposure in API responses, open redirect detection, cookie SameSite validation |
| A02:2021 | Cryptographic Failures | HSTS enforcement, TLS deep analysis (certificate, protocol, cipher suites, testssl.sh integration), Referrer-Policy, JWT alg:none bypass, weak HMAC signing detection, insecure HTTP client configuration (trustAll, verifyHost, rejectUnauthorized) |
| A03:2021 | Injection | SQL injection probes, Cross-Site Scripting (XSS) detection, GraphQL argument injection testing, AI prompt injection & guardrail bypass, CRLF injection (header injection via CR/LF), prototype pollution (__proto__, constructor.prototype) |
| A04:2021 | Insecure Design | GraphQL batch query abuse, query depth limiting, business logic testing (debug endpoints, stack trace exposure) |
| A05:2021 | Security Misconfiguration | Missing/weak security headers (CSP, X-Frame-Options, X-Content-Type-Options), CORS misconfiguration, dangerous HTTP methods, debug endpoint detection, verbose header exposure, GraphQL introspection, HTTP request smuggling (CL.TE / TE.CL desync), cookie security flags (HttpOnly, Secure) |
| A06:2021 | Vulnerable and Outdated Components | Dependency/SCA scanning via OSV-Scanner or Trivy (pom.xml, package.json, go.mod, requirements.txt, Gemfile.lock, build.gradle, Pipfile.lock, package-lock.json) |
| A07:2021 | Identification and Authentication Failures | Brute-force/rate-limiting detection, account enumeration, session handling, token reuse after logout/expiry, JWT expired token acceptance, insecure HTTP client TLS configuration, AI toxicity filter bypass |
| A10:2021 | Server-Side Request Forgery (SSRF) | SSRF probe via URL/redirect/callback parameter injection with internal IP and cloud metadata payloads |

**Reference:** [https://owasp.org/Top10/](https://owasp.org/Top10/)

---

### OWASP API Security Top 10:2023

**What it is:** The OWASP API Security Top 10 addresses the unique security risks of APIs, maintained separately from the Web Application Top 10. It reflects the most critical risks specific to REST, GraphQL, and SOAP APIs.

**How Ghoststrike aligns:**

- Findings are mapped to the relevant API Security category where applicable (via CWE-first, then category-based lookup).
- Reports include an API Security Top 10 coverage summary with per-category finding counts.
- JSON output includes `apiSecurityCategory` on every finding.

| API Security Category | Description | Ghoststrike Coverage |
|-----------------------|-------------|----------------------|
| API1:2023 | Broken Object Level Authorization | Authenticated multi-role scanning: vertical escalation (CWE-269), horizontal escalation / IDOR (CWE-639) |
| API2:2023 | Broken Authentication | Brute-force (CWE-307), account enumeration (CWE-203), rate-limiting, session handling |
| API3:2023 | Broken Object Property Level Authorization | Mass assignment testing (CWE-915), CSRF detection (CWE-352), SQL injection, prototype pollution (CWE-1321) |
| API4:2023 | Unrestricted Resource Consumption | GraphQL batch query abuse (CWE-770), query depth limiting (CWE-400), HTTP request smuggling resource abuse (CWE-444) |
| API5:2023 | Broken Function Level Authorization | Authenticated multi-role scanning: role-based endpoint access control testing (CWE-284) |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Business logic testing (debug endpoints, workflow detection) |
| API7:2023 | Server Side Request Forgery | SSRF probe via URL/redirect/callback parameter injection (CWE-918) |
| API8:2023 | Security Misconfiguration | CORS (CWE-942), dangerous HTTP methods, debug endpoints (CWE-215), GraphQL introspection, verbose headers (CWE-209), clickjacking (CWE-1021), security headers (CWE-693), TLS, cookie security flags (CWE-1004, CWE-614, CWE-1275), HTTP request smuggling (CWE-444), insecure HTTP client config (CWE-295) |
| API9:2023 | Improper Inventory Management | Sensitive path/endpoint discovery (CWE-538), GraphQL endpoint detection, information disclosure (CWE-200), secret/credential exposure in API responses |
| API10:2023 | Unsafe Consumption of APIs | Dependency/SCA scanning via OSV-Scanner or Trivy (CWE-502, CWE-1104), insecure HTTP client configuration (trustAll, verifyHost, h2c) |

**Reference:** [https://owasp.org/API-Security/editions/2023/en/0x11-t10/](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

---

### PTES — Penetration Testing Execution Standard

**What it is:** PTES defines a repeatable methodology for conducting penetration tests across seven phases. It is widely adopted as a baseline for professional penetration testing engagements.

**How Ghoststrike aligns:**

| PTES Phase | Ghoststrike Coverage |
|------------|----------------------|
| Phase 1 — Pre-engagement Interactions | Outside platform scope (handled by the organisation) |
| Phase 2 — Intelligence Gathering | Reconnaissance, sensitive file/path discovery, technology fingerprinting, GraphQL endpoint detection |
| Phase 3 — Threat Modeling | Findings categorised by severity, mapped to risk areas, attack scenario chaining (11 templates) |
| Phase 4 — Vulnerability Analysis | Automated vulnerability scanning across headers, auth, injection, TLS, business logic, GraphQL, SSRF, access control, dependencies, JWT security, cookie flags, HTTP smuggling, CRLF injection, open redirect, prototype pollution, AI prompt injection, secret exposure, URL normalisation bypass, insecure HTTP client config |
| Phase 5 — Exploitation | SQL injection, XSS, directory traversal, CORS abuse, CSRF, mass assignment, GraphQL injection, SSRF, privilege escalation, IDOR, JWT alg:none bypass, HTTP request smuggling, CRLF header injection, prototype pollution, open redirect, AI jailbreak |
| Phase 6 — Post-Exploitation | Outside platform scope |
| Phase 7 — Reporting | Structured reports with executive summary, security grading (A–F), remediation action plan, PoC evidence, attack scenarios, trend analysis, ticketing integration |

**Reference:** [http://www.pentest-standard.org/](http://www.pentest-standard.org/)

---

### NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment

**What it is:** Published by the National Institute of Standards and Technology, SP 800-115 provides guidance for organisations on planning and conducting technical information security testing.

**How Ghoststrike aligns:**

| NIST SP 800-115 Phase | Ghoststrike Coverage |
|-----------------------|----------------------|
| Discovery | Target enumeration, port/service identification, sensitive file discovery, GraphQL endpoint detection, dependency manifest analysis |
| Attack | Active vulnerability testing (injection, authentication, misconfiguration, TLS, business logic, GraphQL, SSRF, access control) |
| Reporting | Structured findings with severity, CVSSv3.1 scores, CWE references, ATT&CK mapping, PoC artifacts, remediation guidance, and ticketing integration |

**Reference:** [https://csrc.nist.gov/publications/detail/sp/800-115/final](https://csrc.nist.gov/publications/detail/sp/800-115/final)

---

### CWE Top 25 — Common Weakness Enumeration

**What it is:** The CWE Top 25 Most Dangerous Software Weaknesses is a list maintained by MITRE that identifies the most common and impactful software security weaknesses. Each weakness has a unique identifier (CWE-ID).

**How Ghoststrike aligns:**

- Every finding includes the relevant CWE ID where applicable.
- CWE links are included in reports for traceability.
- Each CWE is mapped to a CVSSv3.1 vector, ATT&CK technique, and OWASP API Security category.

| CWE ID | Weakness | Ghoststrike Test Area |
|--------|----------|----------------------|
| CWE-20 | Improper Input Validation | URL normalisation bypass (host header manipulation) |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) | Directory traversal checks, URL normalisation bypass (percent-encoding, dot-segments, double-slashes) |
| CWE-77 | Improper Neutralization of Special Elements used in a Command (Command Injection) | AI prompt injection / jailbreak detection |
| CWE-79 | Improper Neutralization of Input During Web Page Generation (XSS) | Cross-Site Scripting detection |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) | SQL injection probes, GraphQL argument injection |
| CWE-93 | Improper Neutralization of CRLF Sequences in HTTP Headers | CRLF injection / HTTP response splitting |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Referrer-Policy, information disclosure, GraphQL introspection, secret/credential exposure in API responses |
| CWE-203 | Observable Discrepancy | Account enumeration detection |
| CWE-209 | Generation of Error Message Containing Sensitive Information | Stack trace exposure detection |
| CWE-215 | Insertion of Sensitive Information Into Debugging Code | Debug endpoint and verbose header detection |
| CWE-269 | Improper Privilege Management | Vertical privilege escalation (authenticated scanning) |
| CWE-284 | Improper Access Control | Authenticated endpoint access control, session handling |
| CWE-295 | Improper Certificate Validation | TLS certificate validation checks, insecure HTTP client config (trustAll, verifyHost, rejectUnauthorized) |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | Brute-force / rate-limiting checks |
| CWE-311 | Missing Encryption of Sensitive Data | HSTS enforcement |
| CWE-319 | Cleartext Transmission of Sensitive Information | TLS protocol enforcement, HTTP-to-HTTPS |
| CWE-326 | Inadequate Encryption Strength | TLS cipher suite and protocol version analysis, JWT weak HMAC signing detection |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | JWT alg:none bypass |
| CWE-352 | Cross-Site Request Forgery (CSRF) | Missing CSRF token detection on login forms |
| CWE-400 | Uncontrolled Resource Consumption | GraphQL query depth limit testing |
| CWE-444 | Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling) | CL.TE / TE.CL desync probe detection |
| CWE-502 | Deserialization of Untrusted Data | Dependency vulnerability detection (SCA) |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | Sensitive file/path exposure |
| CWE-601 | URL Redirection to Untrusted Site (Open Redirect) | Open redirect detection on auth callback endpoints |
| CWE-613 | Insufficient Session Expiration | JWT expired token acceptance |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | Cookie security flag validation |
| CWE-639 | Authorization Bypass Through User-Controlled Key | Horizontal escalation / IDOR detection |
| CWE-693 | Protection Mechanism Failure | Security headers (CSP, X-Frame-Options), HTTP method checks, AI toxicity filter bypass |
| CWE-770 | Allocation of Resources Without Limits or Throttling | GraphQL batch query abuse detection |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | Mass assignment testing |
| CWE-918 | Server-Side Request Forgery (SSRF) | SSRF probe via URL/redirect/callback parameter injection |
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains | CORS misconfiguration |
| CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag | Session cookie HttpOnly flag validation |
| CWE-1021 | Improper Restriction of Rendered UI Layers | X-Frame-Options / clickjacking |
| CWE-1104 | Use of Unmaintained Third-Party Components | Outdated dependency detection (SCA) |
| CWE-1275 | Sensitive Cookie with Improper SameSite Attribute | Cookie SameSite attribute validation |
| CWE-1321 | Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution) | __proto__ and constructor.prototype injection in JSON APIs |

**Reference:** [https://cwe.mitre.org/top25/](https://cwe.mitre.org/top25/)

---

### CVSSv3.1 — Common Vulnerability Scoring System

**What it is:** CVSS is an open standard for assessing the severity of computer system security vulnerabilities. Version 3.1 provides a numerical score (0.0–10.0) and a vector string that describes the attack characteristics.

**How Ghoststrike aligns:**

- Every finding includes a CVSSv3.1 base score and full vector string.
- Scores are computed from the standard vector components: Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI), Scope (S), Confidentiality (C), Integrity (I), Availability (A).
- Severity bands follow the CVSS specification: Critical (9.0–10.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9).
- Reports include the vector string for each finding (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

**Reference:** [https://www.first.org/cvss/specification-document](https://www.first.org/cvss/specification-document)

---

### MITRE ATT&CK — Adversarial Tactics, Techniques, and Common Knowledge

**What it is:** ATT&CK is a knowledge base maintained by MITRE that catalogues adversary behaviour, mapping real-world attack techniques to tactics across the cyber kill chain.

**How Ghoststrike aligns:**

- Every finding is mapped to the relevant ATT&CK technique(s) and tactic(s).
- Reports include an ATT&CK coverage summary table.

| ATT&CK Technique | Name | Tactic | Ghoststrike Test Area |
|-------------------|------|--------|----------------------|
| T1005 | Data from Local System | Collection | Path traversal |
| T1040 | Network Sniffing | Credential Access | Cleartext transmission (TLS/CWE-319) |
| T1078 | Valid Accounts | Privilege Escalation | Authenticated role testing, vertical escalation (CWE-269, CWE-639) |
| T1083 | File and Directory Discovery | Discovery | Path traversal, sensitive file exposure |
| T1087 | Account Discovery | Discovery | Account enumeration |
| T1098 | Account Manipulation | Persistence | Mass assignment (CWE-915) |
| T1110 | Brute Force | Credential Access | Authentication testing |
| T1185 | Browser Session Hijacking | Collection | XSS, cookie security flag weaknesses |
| T1189 | Drive-by Compromise | Initial Access | XSS, CORS misconfiguration, CSRF, clickjacking, open redirect |
| T1190 | Exploit Public-Facing Application | Initial Access | SQL injection, security misconfiguration, GraphQL, business logic, SSRF, SCA, prototype pollution, CRLF injection, HTTP request smuggling, AI prompt injection |
| T1195 | Supply Chain Compromise | Initial Access | Vulnerable dependency detection (SCA) |
| T1499 | Endpoint Denial of Service | Impact | GraphQL batch abuse, resource exhaustion (CWE-770, CWE-400) |
| T1550 | Use Alternate Authentication Material | Defense Evasion | Token reuse after logout/expiry (CWE-284), JWT alg:none bypass, expired JWT acceptance |
| T1557 | Adversary-in-the-Middle | Credential Access | TLS/HSTS, encryption, certificate validation, insecure HTTP client config (trustAll, verifyHost) |
| T1592 | Gather Victim Host Information | Reconnaissance | Information disclosure, debug info, stack traces, secret/credential exposure in API responses |

**Reference:** [https://attack.mitre.org/](https://attack.mitre.org/)

---

### ISO/IEC 27001 — Information Security Management (Full Annex A)

**What it is:** ISO/IEC 27001 is the international standard for information security management systems (ISMS). Annex A defines security controls that organisations can implement.

**How Ghoststrike aligns:**

- Every finding is mapped to the relevant ISO 27001 Annex A control(s).
- Reports include an ISO 27001 control coverage table.

| ISO 27001 Control | Title | Ghoststrike Coverage |
|--------------------|-------|----------------------|
| A.9.4.1 | Information access restriction | Authenticated access control testing, vertical/horizontal escalation |
| A.9.4.2 | Secure log-on procedures | Authentication findings (brute force, enumeration), access control |
| A.9.4.3 | Password management system | Authentication findings |
| A.10.1.1 | Policy on the use of cryptographic controls | TLS findings (protocol, cipher suite, certificate) |
| A.12.5.1 | Installation of software on operational systems | Security misconfiguration findings, SCA |
| A.12.6.1 | Management of technical vulnerabilities | Nikto, Nuclei, information disclosure, misconfiguration, SCA |
| A.14.1.2 | Securing application services on public networks | Security headers, CORS, TLS, GraphQL, SSRF findings |
| A.14.2.5 | Secure system engineering principles | SQL injection, XSS, path traversal, business logic, GraphQL, access control, SCA, SSRF |
| A.14.2.8 | System security testing | OWASP ZAP, business logic testing, overall assessment |
| A.18.1.4 | Privacy and protection of PII | Information disclosure findings |

**Reference:** [https://www.iso.org/standard/27001](https://www.iso.org/standard/27001)

---

### CVE — Common Vulnerabilities and Exposures

**What it is:** The CVE system provides a reference for publicly known information-security vulnerabilities and exposures. Each entry has a unique identifier (CVE-ID).

**How Ghoststrike aligns:**

- When Nuclei is installed, scans check against known CVEs using Project Discovery's template library.
- When OSV-Scanner or Trivy is installed, dependency scans identify CVEs in third-party packages.
- CVE references are included in findings where a known vulnerability matches.

**Reference:** [https://cve.mitre.org/](https://cve.mitre.org/)

---

## 2. Regulatory Awareness

Ghoststrike reports reference the following regulations in business-risk context. While Ghoststrike does not perform regulatory compliance audits, its findings directly support compliance programmes for these regulations.

| Regulation | Relevance |
|------------|-----------|
| **GDPR** (General Data Protection Regulation) | Findings involving data exposure, weak access controls, or injection vulnerabilities are flagged as potential GDPR risk factors. Business impact assessments include legal/reputational dimensions. |
| **PCI DSS** (Payment Card Industry Data Security Standard) | Findings related to encryption, TLS configuration, access control, and vulnerability management support PCI DSS requirements (notably Requirements 6 and 11). |

---

## 3. Testing Tools & Methodology

Ghoststrike uses a combination of built-in tests and optional external tools. All are aligned with the standards above.

### Built-in Testing Modules

| Module | What It Tests |
|--------|---------------|
| Headers | CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy |
| Auth | Brute-force detection, account enumeration, session handling |
| SQLi | SQL injection via configurable payload lists |
| XSS | Cross-Site Scripting via configurable payload lists |
| Recon | Sensitive file/path discovery, technology fingerprinting |
| CORS | Cross-Origin Resource Sharing misconfiguration |
| Traversal | Directory/path traversal |
| Config | Dangerous HTTP methods (OPTIONS, TRACE, PUT, DELETE, CONNECT) |
| TLS | SSL/TLS certificate validation, protocol version, cipher suite strength, optional testssl.sh deep analysis |
| Business Logic | Debug endpoint detection, verbose header exposure, CSRF validation, mass assignment testing, stack trace exposure |
| GraphQL | Endpoint detection, introspection testing, batch query abuse, argument injection, query depth limit testing |
| SSRF | Server-Side Request Forgery probe via URL/redirect/callback parameter injection with internal IP (127.0.0.1, ::1, hex, decimal) and cloud metadata (AWS, GCP) payloads |
| Auth-Roles | Authenticated multi-role scanning: vertical/horizontal privilege escalation, IDOR detection, session/token handling (requires auth profiles) |
| SCA | Dependency vulnerability scanning via OSV-Scanner or Trivy (pom.xml, package.json, package-lock.json, go.mod, requirements.txt, Gemfile.lock, build.gradle, Pipfile.lock) |
| AI Prompt | AI prompt injection detection: jailbreak payloads (DAN, system prompt leakage, admin overrides) and toxicity filter bypass via string obfuscation (underscore, space, leetspeak, dot separation) |
| Secret Leak | Client secret/credential exposure detection in API GET responses: clientSecret, apiKey, password, privateKey, accessToken, refreshToken fields |
| URL Norm | URL normalisation bypass testing: percent-encoding, double-slashes, dot-segments, path traversal, mixed case, trailing dots, host header manipulation |
| HTTP Client | Insecure HTTP client configuration detection: trustAll(true), verifyHost(false), http2ClearTextUpgrade(true), rejectUnauthorized(false) in API policies |
| JWT | JWT security testing: alg:none signature bypass, expired token acceptance, weak HMAC symmetric signing detection |
| Cookie Flags | Cookie security flag validation: HttpOnly, Secure, SameSite attributes on session/auth cookies |
| Smuggling | HTTP request smuggling detection: CL.TE and TE.CL desync probes with timing and content reflection analysis |
| CRLF | CRLF injection / HTTP response splitting: header injection via CR/LF characters in query parameters |
| Redirect | Open redirect detection: unvalidated redirects to attacker-controlled domains via redirect/callback parameters on auth endpoints |
| Proto Pollution | JavaScript prototype pollution: __proto__ and constructor.prototype injection in JSON API endpoints (POST, PUT, PATCH) |

### Optional External Tools

| Tool | Purpose | Standard Alignment |
|------|---------|-------------------|
| **Nikto** | Web server misconfiguration and outdated software detection | OWASP A05, NIST SP 800-115 |
| **Nuclei** | Template-based CVE and misconfiguration scanning | CVE, CWE, OWASP |
| **OWASP ZAP** | Dynamic Application Security Testing (DAST) baseline scan | OWASP Top 10, NIST SP 800-115 |
| **Wapiti** | Black-box web application vulnerability scanner | OWASP Top 10, CWE |
| **testssl.sh** | Comprehensive TLS/SSL analysis (cipher suites, vulnerabilities, certificate chain) | PCI DSS, OWASP A02 |
| **OSV-Scanner** | Open source dependency vulnerability scanning against the OSV database | CVE, CWE, OWASP A06 |
| **Trivy** | Comprehensive SCA for manifests, containers, and filesystems | CVE, CWE, OWASP A06 |

### Payload Sources

| Source | What It Provides |
|--------|-----------------|
| **PayloadsAllTheThings** | Community-maintained SQL injection and XSS payloads (Auth Bypass, FUZZDB, RSNAKE XSS, XSS Polyglots) |
| **Nuclei Templates** (Project Discovery) | CVE detection, misconfiguration checks, exposure and subdomain takeover detection |

---

## 4. Report Compliance Output

Every Ghoststrike report includes:

1. **Executive Summary** — Non-technical overview with security grade (A–F), top risks, recommended immediate actions, positive findings, and coverage depth (authenticated vs unauthenticated).
2. **Security Grade** — Letter grade (A–F) derived from the numeric security score, with risk-level classification.
3. **Authentication Mode** — Colour-coded banner and header identifying authenticated (green) or unauthenticated (orange) scan, with auth method, role, and coverage depth details.
4. **Standards Compliance Table** — Lists each framework and what was covered, including OWASP API Security coverage breakdown.
5. **OWASP & CWE Mapping** — Each finding includes its OWASP Top 10 category, API Security Top 10 category, and CWE ID.
6. **CVSSv3.1 Scoring** — Base score and vector string on every finding.
7. **Business Impact Assessment** — Financial, operational, reputational, and legal impact ratings per finding with rationale.
8. **Remediation Action Plan** — Priority (P1–P4), complexity (Low/Medium/High), and timeframe per finding.
9. **MITRE ATT&CK Mapping** — Technique and tactic mapping with ATT&CK coverage summary table.
10. **ISO 27001 Controls** — Annex A control mapping per finding with coverage table.
11. **Proof of Concept (PoC)** — curl commands, raw request/response snippets, and reproduction steps per finding.
12. **Attack Scenarios** — Chained multi-finding attack narratives with likelihood and impact ratings (11 scenario templates).
13. **Trend Analysis** — Comparison with previous scans showing new, resolved, and persisting findings. Includes cross-mode warnings when comparing authenticated vs unauthenticated scans.
14. **Auth Context** — For authenticated scanning findings: discovered-as role, exploitable-as role, required privilege level, endpoint, pre-auth/post-auth classification, and per-tool authentication capability matrix.
15. **Coverage Depth** — Pre-auth vs post-auth finding breakdown, with a warning when an authenticated scan produces zero post-auth findings.
16. **Glossary** — Definitions of CWE, CVE, CVSS, DAST, OWASP, OWASP API Top 10, PTES, NIST SP 800-115, ATT&CK, ISO 27001, XSS, SQLi, and CORS.
17. **JSON Export** — Machine-readable report with full compliance, finding, enrichment, API Security, and auth-mode data.
18. **PDF Export** — Printable PDF report mirroring the Markdown structure with colour-coded auth-mode styling.
19. **Jira / GitHub / Linear Integration** — Findings above a configurable severity threshold are automatically pushed to the configured issue tracker with full field mapping, deduplication, and trend-aware commenting.

### JSON Compliance Structure

```json
{
  "compliance": {
    "frameworks": [
      "OWASP Top 10:2021",
      "OWASP API Security Top 10:2023",
      "PTES",
      "NIST SP 800-115",
      "CWE Top 25",
      "CVSSv3.1",
      "MITRE ATT&CK",
      "ISO/IEC 27001"
    ],
    "toolsUsed": ["headers", "auth", "sqli", "xss", "recon", "cors", "traversal", "config", "tls", "logic", "graphql", "ssrf", "auth-roles", "sca", "ai-prompt", "secret-leak", "url-norm", "http-client", "jwt", "cookie-flags", "smuggling", "crlf", "redirect", "proto-pollution"]
  },
  "summary": {
    "securityScore": 78,
    "securityGrade": { "grade": "C", "label": "Adequate" },
    "riskLevel": "medium",
    "totalFindings": 5,
    "bySeverity": { "critical": 0, "high": 1, "medium": 2, "low": 1, "info": 1 }
  },
  "findings": [
    {
      "title": "Missing CSP Header",
      "severity": "medium",
      "cvss": { "version": "3.1", "baseScore": 5.3, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/..." },
      "businessImpact": { "financial": "Low", "operational": "Low", "reputational": "Low", "legal": "Low" },
      "remediation": { "complexity": "Low", "priority": "P2", "timeframe": "2 weeks" },
      "attackTechniques": [{ "techniqueId": "T1190", "tactic": "Initial Access" }],
      "iso27001Controls": ["A.14.1.2"],
      "apiSecurityCategory": { "id": "API8:2023", "name": "Security Misconfiguration" },
      "authContext": null,
      "poc": { "curlCommand": "curl ...", "reproductionSteps": ["..."] }
    }
  ],
  "scenarios": [],
  "trend": null
}
```

### CI/CD Pipeline Integration

Ghoststrike provides a dedicated CI/CD API endpoint for automated security gates:

- **Pass/fail** based on configurable severity threshold (`critical`, `high`, `medium`, `low`).
- **Structured JSON output** including security score, grade, risk level, finding counts, and details.
- **Exit code** 0 (pass) or 1 (fail) for pipeline integration.

### Ticketing Integration

Ghoststrike can push findings directly to issue trackers via a configurable API:

- **Supported platforms:** Jira Cloud, GitHub Issues, Linear
- **Severity filtering:** Configurable minimum severity threshold per provider
- **Jira field mapping:** Summary, priority (Blocker/Critical/Major/Minor), description with CVSS, PoC, ATT&CK, business impact, CWE/OWASP labels
- **Deduplication:** Title + target matching to avoid duplicate tickets; trend-aware commenting on existing open issues
- **Reopen resolved:** Optionally reopens resolved tickets when a finding re-appears
- **Dry-run mode:** Preview what would be created without posting

---

## 5. Scope & Limitations

Ghoststrike is an **automated** security assessment platform. The following points should be considered when evaluating compliance:

- **Automated testing** — Ghoststrike does not replace manual penetration testing. Complex chained attacks and some business-process vulnerabilities require human assessment. (Note: Ghoststrike includes automated business logic tests, SSRF probing, and 11 attack scenario chain templates.)
- **No post-exploitation** — The platform identifies and probes vulnerabilities but does not perform post-exploitation activities (lateral movement, data exfiltration).
- **Authenticated scanning requires configuration** — Multi-role privilege escalation, IDOR tests, and post-authentication coverage require the user to provide auth profiles (bearer tokens, basic credentials, or form login). Without profiles, auth-roles scanning is skipped and all findings are classified as pre-authentication. Reports include a coverage depth summary and a warning when authenticated scans produce zero post-auth findings.
- **SCA requires external scanners** — Dependency vulnerability scanning requires OSV-Scanner or Trivy to be installed, and a manifest file path to be provided.
- **Pre-engagement and post-engagement** — Scoping, rules of engagement, and remediation verification are the organisation's responsibility.
- **External tools are optional** — Nikto, Nuclei, OWASP ZAP, Wapiti, and testssl.sh extend coverage but must be installed and maintained by the operator.
- **Point-in-time assessment** — Results reflect the state of the target at the time of scanning. Regular re-testing is recommended (trend analysis compares consecutive scans automatically).

---

## 6. Summary

| Standard / Framework | Type | Primary Use in Ghoststrike |
|----------------------|------|---------------------------|
| OWASP Top 10:2021 | Application Security | Finding categorisation, risk mapping (A01–A07, A10) |
| OWASP API Security Top 10:2023 | API Security | API-specific finding categorisation (API1–API10) |
| CVSSv3.1 | Scoring System | Base score and vector string on every finding |
| MITRE ATT&CK | Threat Intelligence | Technique and tactic mapping per finding (15 techniques) |
| PTES | Methodology | Testing phases, report structure |
| NIST SP 800-115 | Guideline | Testing phases, report compliance |
| CWE Top 25 | Weakness Catalogue | Finding identification (37 CWE IDs mapped) |
| ISO/IEC 27001 | Management Standard | Annex A controls: A.9, A.10, A.12, A.14, A.18 (10 controls) |
| CVE | Vulnerability Catalogue | Known vulnerability detection (via Nuclei, OSV-Scanner, Trivy) |
| GDPR | Regulation | Business risk context, legal impact assessment |
| PCI DSS | Regulation | Business risk context, TLS/encryption compliance |

---

*This document is maintained alongside the Ghoststrike platform. For methodology details, see [PENTEST_METHODOLOGY.md](./PENTEST_METHODOLOGY.md).*
