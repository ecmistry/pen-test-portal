# Ghoststrike — Automated Penetration Testing Platform

## Overview

Ghoststrike is an automated penetration testing portal that combines **Dynamic Application Security Testing (DAST)** and **Static Application Security Testing (SAST)** to deliver comprehensive vulnerability assessments of web applications. It scans live applications over HTTP *and* analyses source code in Git repositories, linking findings to specific URLs, components, and source file locations.

The platform is accessible at [ghoststrike.tech](https://ghoststrike.tech) and produces professional-grade reports aligned with industry standards including OWASP Top 10:2021, PTES, NIST SP 800-115, CWE Top 25, CVSSv3.1, MITRE ATT&CK, OWASP API Security Top 10:2023, and ISO/IEC 27001.

---

## How It Works

### Targets

A **target** represents an application to scan. Each target has:

- **Name** — human-readable label
- **URL** — the live application endpoint (used for DAST)
- **Repository URL** *(optional)* — a Git repository URL (used for SAST via Semgrep)
- **Description, Tags, Scan Frequency** — metadata and scheduling

### Scan Modes

| Mode | Scope | Duration |
|------|-------|----------|
| **Light** | Fast check — headers, auth, SQLi, XSS, recon with reduced payloads | < 1 minute |
| **Full** | Complete assessment — all 28+ built-in modules plus external tools (Nikto, Nuclei, Wapiti, ZAP) and SAST if a repo URL is configured | Several minutes |

---

## DAST — Dynamic Application Security Testing

DAST tests the running application by sending HTTP requests and analysing responses. Ghoststrike includes **24 built-in DAST modules** that run without any external tool dependencies:

### Core Security Checks (Light + Full)

| Module | What It Tests |
|--------|--------------|
| **Headers** | Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **Auth** | Brute force protection, account enumeration, session/cookie handling |
| **SQLi** | SQL injection via error-based and behavioural probes (PayloadsAllTheThings-sourced) |
| **XSS** | Reflected cross-site scripting including polyglot payloads |
| **Recon** | Sensitive file exposure (.env, .git/config, backups), technology fingerprinting, SPA-aware false positive filtering |

### Extended Checks (Full Mode)

| Module | What It Tests |
|--------|--------------|
| **CORS** | Permissive or origin-reflecting CORS policies |
| **Directory Traversal** | Path traversal (../etc/passwd, encoded variants) on common parameters |
| **Config / HTTP Methods** | OPTIONS, TRACE, PUT, DELETE, CONNECT — flags risky enabled methods |
| **TLS/SSL** | Certificate validation, protocol versions, cipher strength (optional deep analysis via testssl.sh) |
| **Business Logic** | Debug endpoints, CSRF, mass assignment, stack trace exposure |
| **GraphQL** | Endpoint detection, introspection, batch query abuse, injection |
| **SSRF** | Server-Side Request Forgery via URL/redirect/callback parameter injection |
| **AI Prompt Injection** | Jailbreak prompts, guardrail bypass, toxicity filter obfuscation on LLM endpoints |
| **Secret Exposure** | Credential leakage (clientSecret, apiKey, password, tokens) in API responses |
| **URL Normalisation Bypass** | Percent-encoding, double-slash, dot-segment, hostname tricks to bypass ACLs |
| **Insecure HTTP Client** | trustAll(true), verifyHost(false), H2C upgrade, rejectUnauthorized(false) in policy configs |
| **JWT Security** | alg:none bypass, expired token acceptance, weak HMAC detection |
| **Cookie Security** | HttpOnly, Secure, SameSite flag validation on session cookies |
| **HTTP Request Smuggling** | CL.TE and TE.CL desync probes via raw TCP/TLS |
| **CRLF Injection** | Header injection via CR/LF in query parameters (response splitting, cache poisoning) |
| **Open Redirect** | Unvalidated redirects on auth paths (login, OAuth, SSO callbacks) |
| **Prototype Pollution** | `__proto__` and `constructor.prototype` injection in JSON API endpoints |

### External Tool Integration (Full Mode, Optional)

| Tool | What It Adds |
|------|-------------|
| **Nikto** | Web server misconfigurations, outdated software, default files |
| **Nuclei** | CVE detection, misconfiguration checks, exposure/takeover via community templates |
| **Wapiti** | Black-box crawler with SQLi, XSS, XXE, file disclosure modules |
| **OWASP ZAP** | Session-aware crawling and authenticated DAST baseline scan |

---

## SAST — Static Application Security Testing

SAST analyses the application's **source code** to find vulnerabilities that are invisible to DAST (e.g., insecure code patterns, hardcoded secrets, dangerous function calls).

### How It Works

1. When a target has a **Repository URL** configured, the SAST module activates during full-mode scans
2. The scanner **clones the repository** (shallow, single-branch for speed)
3. **Semgrep** (v1.136.0) runs against the codebase with `--config auto`, which includes thousands of community-maintained security rules
4. Results are parsed and each finding includes:
   - **Source file path** — exact file in the repository
   - **Line number** — precise line where the issue occurs
   - **Code snippet** — surrounding source code with markers (`>>>`) on the problematic lines
   - **CWE and OWASP mapping** — automatically extracted from Semgrep rule metadata
   - **Confidence level** — LOW / MEDIUM / HIGH from the rule engine
   - **Rule reference** — link to the Semgrep rule documentation

### What SAST Detects

Semgrep's auto-config includes rules for:

- **Injection** — eval(), exec(), SQL string concatenation, template injection, command injection
- **Cryptographic Issues** — weak algorithms, hardcoded keys, insecure random
- **Authentication** — hardcoded credentials, missing auth checks
- **Input Validation** — missing sanitisation, path traversal, XSS sinks
- **Configuration** — debug mode enabled, insecure defaults, CORS misconfig in code
- **Dependency Patterns** — insecure imports, deprecated APIs
- **Language-specific** — covers JavaScript/TypeScript, Python, Java, Go, Ruby, PHP, C#, Kotlin, Rust, and more

### DAST + SAST Combined Value

| Capability | DAST Only | SAST Only | DAST + SAST |
|-----------|-----------|-----------|-------------|
| Finds runtime misconfigurations | Yes | No | Yes |
| Finds insecure code patterns | No | Yes | Yes |
| Tests real HTTP behaviour | Yes | No | Yes |
| Pinpoints exact source file/line | No | Yes | Yes |
| Detects hardcoded secrets in code | Limited | Yes | Yes |
| Finds injection via user input | Yes | Yes | Yes (dual validation) |
| Actionable for developers | URL + component level | File + line level | Both — full traceability |

---

## Authenticated Scanning

Ghoststrike supports **authenticated scans** using:

- **Bearer tokens** — API key or JWT passed as `Authorization: Bearer <token>`
- **Basic credentials** — username/password as HTTP Basic Auth
- **Form login** — automated login via HTML form or JSON POST, with session cookie capture

### What Authenticated Scanning Adds

| Aspect | Unauthenticated | Authenticated |
|--------|----------------|---------------|
| **Perspective** | External attacker, no credentials | Attacker with valid session |
| **Coverage** | Public endpoints only | Post-login pages, protected APIs, admin panels |
| **Finding context** | All pre-authentication | Tagged as pre-auth or post-auth |
| **Extra tests** | — | Vertical/horizontal privilege escalation, IDOR, session handling |

### Multi-Role Testing

When multiple auth profiles are provided (e.g., admin + standard user), Ghoststrike tests:

- **Vertical Privilege Escalation** — can a low-privilege user access admin endpoints?
- **Horizontal Privilege Escalation (IDOR)** — can one user access another user's resources?
- **Session Expiry** — does the server enforce session timeouts?

---

## SCA — Software Composition Analysis

When a **manifest file** path is provided (e.g., `package.json`, `requirements.txt`, `pom.xml`), Ghoststrike runs **dependency vulnerability scanning** via OSV-Scanner or Trivy to identify known CVEs in third-party libraries.

---

## Reporting

Every scan produces a professional penetration test report available in three formats:

### Export Formats

| Format | Use Case |
|--------|----------|
| **PDF** | Stakeholder-ready A4 document with sections 1–8 plus appendix |
| **Markdown** | Viewable in-app and downloadable; suitable for documentation workflows |
| **JSON** | Structured data for integration with CI/CD, ticketing, and dashboards |

### Report Structure

1. **Document Control** — Report version, scan ID, target, duration, trigger
2. **Scope of Work** — In scope (target, domains, scan mode) and out of scope
3. **Executive Summary** — Security score, risk level, severity distribution, coverage depth, top risks
4. **Test Coverage** — All modules used, tool authentication capability matrix
5. **Findings Summary** — Numbered table of all findings with severity and category
6. **Detailed Findings** — Per finding:
   - Category, severity, CWE/OWASP/MITRE mapping
   - Description and business impact
   - Evidence (HTTP responses, headers, payloads)
   - **Affected URL and component** (DAST)
   - **Source file, line number, and code snippet** (SAST)
   - Remediation recommendation with priority and complexity
7. **Recommendations** — Immediate, short-term, and long-term actions
8. **Standards Compliance** — OWASP Top 10, PTES, NIST, CWE, ISO 27001, OWASP API Top 10

### Finding Enrichment

Every finding is enriched with:

- **CVSSv3.1 score and vector** — quantitative risk rating
- **CWE ID** — Common Weakness Enumeration reference
- **OWASP category** — Top 10 and API Security Top 10 mapping
- **MITRE ATT&CK techniques** — adversary tactic mapping
- **ISO 27001 controls** — compliance control mapping
- **Remediation priority** (P1–P4) and complexity (Low/Medium/High)
- **Business impact statement** — plain-language risk description

---

## False Positive Reduction

Ghoststrike includes several mechanisms to reduce noise:

- **SPA Detection** — identifies single-page application fallback responses and suppresses false "file found" alerts
- **Content Validation** — verifies that detected files contain expected content, not generic HTML shells
- **Nikto Legacy Filtering** — suppresses outdated CGI probe results (e.g., `/cgi-bin/test-cgi`, `/scripts/cmd.exe`)
- **CSP Interpretation** — avoids flagging CSP policies that are present but use different directive formats
- **Semgrep Confidence Filtering** — only includes WARNING and ERROR severity results from SAST (filters out low-confidence noise)

---

## Payload Updates

Scan payloads can be kept current:

- **PayloadsAllTheThings** — SQL injection and XSS payload lists from the community repository, updated via Admin panel
- **Nuclei Templates** — community-maintained CVE/misconfig templates, updated via `nuclei -update-templates`
- **Semgrep Rules** — automatically fetched from the Semgrep registry with `--config auto` on each scan

---

## Architecture

| Component | Technology |
|-----------|-----------|
| **Frontend** | React + TypeScript + Tailwind CSS + shadcn/ui |
| **Backend** | Node.js + Express + tRPC |
| **Database** | MySQL (via Drizzle ORM) |
| **SAST Engine** | Semgrep (Python, installed on scan server) |
| **External DAST** | Nikto, Nuclei, Wapiti, OWASP ZAP (optional) |
| **Hosting** | Self-hosted on AWS EC2 behind Nginx |

---

## Getting Started

1. **Create a target** — provide the application URL and optionally a Git repository URL for SAST
2. **Run a scan** — choose Light (quick check) or Full (comprehensive) mode
3. **Review findings** — browse results in the UI with affected URLs, components, and source code locations
4. **Generate a report** — export as PDF, Markdown, or JSON for stakeholders
5. **Track remediation** — findings have status tracking (open, acknowledged, resolved, false positive)

### Enabling SAST

To enable source code analysis on a target:

1. Edit the target in the Targets page
2. Enter the Git repository URL (e.g., `https://github.com/org/repo.git`)
3. Run a **Full** scan — SAST will automatically activate alongside DAST
4. SAST findings appear with source file paths, line numbers, and code snippets in both the UI and reports

---

## Limitations

- **Automated only** — does not replace manual penetration testing or expert judgement
- **DAST scope** — tests from an external perspective; internal network vulnerabilities are out of scope
- **SAST scope** — requires a Git-accessible repository; binary-only applications cannot be analysed
- **External tools** — Nikto, Nuclei, Wapiti, and ZAP are third-party; their coverage depends on version and configuration
- **False positives/negatives** — heuristics reduce but cannot eliminate false positives; some vulnerabilities may require manual verification
- **Private repositories** — SAST requires the scan server to have read access (SSH keys or access tokens) for private repos

---

*Ghoststrike — [ghoststrike.tech](https://ghoststrike.tech)*
