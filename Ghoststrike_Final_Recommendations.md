# Ghoststrike — Final Wave Recommendations
> Residual gaps identified after v2 compliance update. Four areas remain unimplemented from the original gap analysis against the Formind penetration testing methodology.

---

## Context

The v2 compliance update successfully implemented CVSSv3.1, MITRE ATT&CK, GraphQL testing, TLS deep analysis, business logic modules, executive summary grading, PoC artifacts, attack scenario chaining, trend analysis, and expanded ISO 27001 coverage.

The following four recommendations remain outstanding.

---

## 1. Authenticated Multi-Role Scanning

### Gap
Ghoststrike currently scans as an unauthenticated user only. It cannot test what an authenticated user with a specific privilege level can access, nor can it detect horizontal or vertical privilege escalation between roles.

### Why It Matters
The majority of high-severity vulnerabilities in API management platforms like Gravitee exist behind authentication. An unauthenticated scan will miss:
- Admin endpoints accessible to standard users (vertical escalation)
- User A accessing User B's data (horizontal / IDOR)
- Endpoints that behave differently depending on role
- Session token handling and expiry behaviour

### Implementation

Add an `authProfiles` configuration block to the scan config:

```json
{
  "authProfiles": [
    {
      "name": "anonymous",
      "type": "none"
    },
    {
      "name": "standard_user",
      "type": "bearer",
      "token": "eyJhbGci..."
    },
    {
      "name": "admin",
      "type": "bearer",
      "token": "eyJhbGci..."
    },
    {
      "name": "read_only",
      "type": "basic",
      "username": "readonly",
      "password": "..."
    }
  ],
  "authTests": {
    "verticalEscalation": true,
    "horizontalEscalation": true,
    "sessionExpiry": true,
    "tokenReuse": true
  }
}
```

**Vertical escalation check:**
- For each endpoint discovered, attempt access using every defined profile
- Flag any endpoint that is accessible at a lower privilege level than expected
- Example finding: `GET /api/admin/users` returns 200 when authenticated as `standard_user`

**Horizontal escalation (IDOR) check:**
- When two or more user-level profiles are defined, attempt to access resources owned by Profile A while authenticated as Profile B
- Target resource ID patterns in URLs: `/api/users/{id}`, `/api/orders/{id}`, `/api/docs/{id}`
- Example finding: `GET /api/users/42` returns User A's data when authenticated as User B

**Session handling checks:**
- Verify tokens are invalidated after logout
- Verify tokens expire after the expected TTL
- Check whether expired tokens are accepted
- Check whether tokens can be reused after password change

**Finding schema additions:**
```json
{
  "id": "F-012",
  "type": "auth",
  "title": "Vertical Privilege Escalation — Admin Endpoint Accessible as Standard User",
  "discoveredAs": "standard_user",
  "exploitableAs": "standard_user",
  "requiredLevel": "admin",
  "endpoint": "GET /api/admin/users",
  "cvss": {
    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "baseScore": 8.1,
    "baseSeverity": "HIGH"
  },
  "owasp": "A01:2021",
  "cwe": "CWE-269",
  "attackTechniques": [
    {
      "techniqueId": "T1078",
      "techniqueName": "Valid Accounts",
      "tactic": "Privilege Escalation"
    }
  ]
}
```

**New CWE mappings to add to COMPLIANCE_STANDARDS.md:**

| CWE ID | Weakness | Ghoststrike Test Area |
|--------|----------|-----------------------|
| CWE-269 | Improper Privilege Management | Vertical privilege escalation |
| CWE-284 | Improper Access Control | Authenticated endpoint access control |
| CWE-639 | Authorization Bypass Through User-Controlled Key | Horizontal escalation / IDOR |

**New ATT&CK mappings to add:**

| ATT&CK Technique | Name | Tactic | Ghoststrike Test Area |
|------------------|------|--------|-----------------------|
| T1078 | Valid Accounts | Privilege Escalation | Authenticated role testing |
| T1550 | Use Alternate Authentication Material | Defense Evasion | Token reuse after logout/expiry |

---

## 2. Dependency / SCA Scanning

### Gap
Ghoststrike has no Software Composition Analysis (SCA) capability. It cannot identify vulnerable third-party libraries or packages shipped with the target application.

### Why It Matters
Dependency vulnerabilities (e.g. Log4Shell, Spring4Shell) represent a major and growing attack surface. Formind explicitly uses Snyk for dependency scanning as part of their static analysis phase. For a platform like Gravitee — which ships as a Java/Node.js product with many dependencies — this is a meaningful blind spot.

### Implementation

Accept a manifest file as optional scan input via `--deps` flag:

```bash
ghoststrike scan --target https://target.com --deps ./pom.xml
ghoststrike scan --target https://target.com --deps ./package.json
ghoststrike scan --target https://target.com --deps ./requirements.txt
ghoststrike scan --target https://target.com --deps ./go.mod
```

**Supported manifest formats:**
- `pom.xml` — Java/Maven
- `build.gradle` — Java/Gradle
- `package.json` / `package-lock.json` — Node.js
- `requirements.txt` / `Pipfile.lock` — Python
- `go.mod` — Go
- `Gemfile.lock` — Ruby

**Integration options (in order of preference):**
1. **OSV-Scanner** (Google, open source) — queries the OSV database, supports all major ecosystems, no API key required
2. **Trivy** (Aqua Security, open source) — supports manifests, container images, and filesystem scanning
3. **Snyk CLI** (freemium) — most comprehensive, requires API key

**Finding schema for dependency vulnerabilities:**
```json
{
  "id": "F-019",
  "type": "dependency",
  "title": "Vulnerable Dependency: jackson-databind 2.13.0 (CVE-2022-42003)",
  "package": "jackson-databind",
  "installedVersion": "2.13.0",
  "fixedVersion": "2.13.4.2",
  "cve": "CVE-2022-42003",
  "cwe": "CWE-502",
  "cvss": {
    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "baseScore": 7.5,
    "baseSeverity": "HIGH"
  },
  "owasp": "A06:2021",
  "remediation": {
    "description": "Upgrade jackson-databind to version 2.13.4.2 or later.",
    "complexity": "Low",
    "priority": "P1",
    "timeframe": "48 hours"
  }
}
```

**New OWASP coverage to add:**

| OWASP Category | Description | Ghoststrike Coverage |
|----------------|-------------|----------------------|
| A06:2021 | Vulnerable and Outdated Components | Dependency/SCA scanning via OSV-Scanner, Trivy, or Snyk |

**New CWE mappings to add:**

| CWE ID | Weakness | Ghoststrike Test Area |
|--------|----------|-----------------------|
| CWE-502 | Deserialization of Untrusted Data | Dependency vulnerability detection |
| CWE-1104 | Use of Unmaintained Third-Party Components | Outdated dependency detection |

**Compliance additions:**

Add to the `toolsUsed` array in the JSON compliance structure:
```json
"toolsUsed": ["headers", "auth", "sqli", "xss", "recon", "cors", "traversal", "config", "tls", "logic", "graphql", "sca"]
```

Add to Optional External Tools table:

| Tool | Purpose | Standard Alignment |
|------|----------|--------------------|
| **OSV-Scanner** | Open source dependency vulnerability scanning against the OSV database | CVE, CWE, OWASP A06 |
| **Trivy** | Comprehensive SCA for manifests, containers, and filesystems | CVE, CWE, OWASP A06 |

---

## 3. OWASP API Security Top 10:2023

### Gap
Ghoststrike currently maps to the OWASP Web Application Top 10:2021. This is appropriate for web applications but insufficient for API-first platforms. The OWASP API Security Top 10 is a distinct list that addresses API-specific risks not covered by the Web Top 10.

### Why It Matters
Gravitee is an API management platform — its core attack surface is APIs, not web pages. Customers evaluating Gravitee's security posture will specifically ask about API security standards. The OWASP API Security Top 10 is the most widely referenced framework for this, and Formind explicitly includes API audit as a distinct test category alongside web application testing.

### Implementation

Add OWASP API Security Top 10:2023 as a standalone framework section in COMPLIANCE_STANDARDS.md:

```markdown
### OWASP API Security Top 10:2023

**What it is:** The OWASP API Security Top 10 addresses the unique security
risks of APIs, maintained separately from the Web Application Top 10.
It reflects the most critical risks specific to REST, GraphQL, and SOAP APIs.

**How Ghoststrike aligns:**
```

| API Security Category | Description | Ghoststrike Coverage |
|-----------------------|-------------|----------------------|
| API1:2023 | Broken Object Level Authorization | Horizontal escalation (IDOR) checks via authenticated multi-role scanning |
| API2:2023 | Broken Authentication | Brute-force, rate-limiting, account enumeration, token expiry checks |
| API3:2023 | Broken Object Property Level Authorization | Mass assignment testing (CWE-915), GraphQL field-level injection |
| API4:2023 | Unrestricted Resource Consumption | GraphQL batch query abuse, query depth limiting (CWE-400, CWE-770) |
| API5:2023 | Broken Function Level Authorization | Vertical privilege escalation via authenticated multi-role scanning |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Business logic testing, workflow step-skipping detection |
| API7:2023 | Server Side Request Forgery (SSRF) | SSRF probe via configurable payload lists |
| API8:2023 | Security Misconfiguration | CORS, dangerous HTTP methods, debug endpoints, GraphQL introspection, verbose headers |
| API9:2023 | Improper Inventory Management | Sensitive path/endpoint discovery, GraphQL endpoint detection |
| API10:2023 | Unsafe Consumption of APIs | Third-party API dependency checks (via SCA module) |

**Reference:** https://owasp.org/API-Security/editions/2023/en/0x11-t10/

**Note on API7:2023 (SSRF):** This requires adding an SSRF probe module if not already present. Minimum viable implementation:
- Send a request with a controlled external URL in common injection points: `url=`, `redirect=`, `callback=`, `next=`, `target=`
- Detect whether the server makes an outbound request to the controlled URL (requires an out-of-band callback receiver, e.g. integration with Burp Collaborator or a self-hosted interactsh instance)
- If out-of-band detection is not available, detect internal IP responses: `127.0.0.1`, `169.254.x.x`, `10.x.x.x`, `192.168.x.x`

**New CWE mappings to add:**

| CWE ID | Weakness | Ghoststrike Test Area |
|--------|----------|-----------------------|
| CWE-918 | Server-Side Request Forgery (SSRF) | SSRF probe module |

**Update the compliance frameworks JSON array:**
```json
"frameworks": [
  "OWASP Top 10:2021",
  "OWASP API Security Top 10:2023",
  "PTES",
  "NIST SP 800-115",
  "CWE Top 25",
  "CVSSv3.1",
  "MITRE ATT&CK",
  "ISO/IEC 27001"
]
```

**Update the summary table in Section 6:**

| Standard / Framework | Type | Primary Use in Ghoststrike |
|----------------------|------|---------------------------|
| OWASP API Security Top 10:2023 | API Security | API-specific finding categorisation (API1–API10) |

---

## 4. Jira / Ticketing Integration

### Gap
Ghoststrike produces reports (Markdown, JSON, PDF) but has no mechanism to push findings directly into issue trackers. Vulnerabilities must be manually transcribed into Jira or equivalent tools.

### Why It Matters
Formind's direct Jira access during the Gravitee engagement was called out as a specific advantage — it removes friction between finding and remediation. For Ghoststrike to be used in a continuous security workflow (every sprint, every release), findings need to flow automatically into the same backlog engineers work from. Without this, scan results risk being filed and forgotten.

### Implementation

Add a `--jira` output flag and an `integrations` config block:

```json
{
  "integrations": {
    "jira": {
      "enabled": true,
      "baseUrl": "https://your-org.atlassian.net",
      "projectKey": "SEC",
      "apiToken": "...",
      "email": "security@your-org.com",
      "minSeverity": "medium",
      "issueType": "Bug",
      "labels": ["ghoststrike", "security"],
      "deduplication": true,
      "reopenResolved": true
    },
    "github": {
      "enabled": false,
      "repo": "your-org/your-repo",
      "token": "...",
      "minSeverity": "high",
      "labels": ["security", "ghoststrike"]
    },
    "linear": {
      "enabled": false,
      "apiKey": "...",
      "teamId": "...",
      "minSeverity": "high"
    }
  }
}
```

**Jira field mapping:**

| Ghoststrike Field | Jira Field |
|-------------------|------------|
| `title` | Summary |
| `severity` → CVSSv3.1 band | Priority (Blocker/Critical/Major/Minor) |
| `description` + `remediation.description` | Description (formatted) |
| `cvss.baseScore` + `cvss.vectorString` | Custom field: CVSS Score |
| `owasp` | Label |
| `cwe` | Label |
| `attackTechniques[].techniqueId` | Label |
| `poc.curlCommand` | Description (code block) |
| `poc.reproductionSteps` | Description (numbered list) |
| `remediation.priority` | Custom field: Remediation Priority |
| `remediation.timeframe` | Custom field: Fix By |
| `businessImpact` | Description (impact table) |

**Deduplication logic:**
- Before creating a new issue, search Jira for existing open issues with matching `title` and `target`
- If found and status is open → add a comment with the new scan date confirming the finding persists
- If found and status is resolved/closed → reopen if `reopenResolved: true`, otherwise create a new issue with a reference to the previously resolved ticket
- Add a `ghoststrike-id` custom field using the finding's stable hash to enable reliable deduplication across scans

**Trend integration:**
- When a finding is resolved between scans (present in scan N, absent in scan N+1), post a Jira comment: `"Finding no longer detected in Ghoststrike scan on {date}. Please verify remediation and close if confirmed."`
- Do not auto-close tickets — leave closure to the engineering team

**CLI usage:**
```bash
# Push all findings above medium severity to Jira
ghoststrike scan --target https://target.com --output jira

# Push only critical and high findings
ghoststrike scan --target https://target.com --output jira --fail-on high

# Dry run — show what would be created without posting
ghoststrike scan --target https://target.com --output jira --dry-run
```

**Add to Report Compliance Output section (Section 4):**

> **16. Jira / GitHub / Linear Integration** — Findings above a configurable severity threshold are automatically pushed to the configured issue tracker with full field mapping, deduplication, and trend-aware commenting.

---

## Updated Compliance Summary Table

Once all four recommendations are implemented, update Section 6 of COMPLIANCE_STANDARDS.md to reflect the final state:

| Standard / Framework | Type | Primary Use in Ghoststrike |
|----------------------|------|---------------------------|
| OWASP Top 10:2021 | Application Security | Finding categorisation, risk mapping (A01–A05, A07) |
| OWASP API Security Top 10:2023 | API Security | API-specific finding categorisation (API1–API10) |
| CVSSv3.1 | Scoring System | Base score and vector string on every finding |
| MITRE ATT&CK | Threat Intelligence | Technique and tactic mapping per finding (14+ techniques) |
| PTES | Methodology | Testing phases, report structure |
| NIST SP 800-115 | Guideline | Testing phases, report compliance |
| CWE Top 25 | Weakness Catalogue | Finding identification (25+ CWE IDs mapped) |
| ISO/IEC 27001 | Management Standard | Annex A controls: A.9, A.10, A.12, A.14, A.18 |
| CVE | Vulnerability Catalogue | Known vulnerability detection (via Nuclei, OSV-Scanner, Trivy) |
| GDPR | Regulation | Business risk context, legal impact assessment |
| PCI DSS | Regulation | Business risk context, TLS/encryption compliance |

---

## Updated Built-in Testing Modules Table

| Module | What It Tests |
|--------|---------------|
| Headers | CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy |
| Auth | Brute-force detection, account enumeration, session handling, multi-role authenticated scanning, token expiry/reuse |
| SQLi | SQL injection via configurable payload lists |
| XSS | Cross-Site Scripting via configurable payload lists |
| Recon | Sensitive file/path discovery, technology fingerprinting |
| CORS | Cross-Origin Resource Sharing misconfiguration |
| Traversal | Directory/path traversal |
| Config | Dangerous HTTP methods (OPTIONS, TRACE, PUT, DELETE, CONNECT) |
| TLS | SSL/TLS certificate validation, protocol version, cipher suite strength, optional testssl.sh deep analysis |
| Business Logic | Debug endpoint detection, verbose header exposure, CSRF validation, mass assignment testing, stack trace exposure, SSRF probing |
| GraphQL | Endpoint detection, introspection testing, batch query abuse, argument injection, query depth limit testing |
| SCA | Dependency vulnerability scanning via OSV-Scanner, Trivy, or Snyk (accepts pom.xml, package.json, go.mod, requirements.txt) |

---

## Updated JSON Compliance Structure

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
    "toolsUsed": [
      "headers", "auth", "sqli", "xss", "recon", "cors",
      "traversal", "config", "tls", "logic", "graphql", "sca"
    ]
  }
}
```

---

## CWE Additions Summary

The following CWE IDs should be appended to the CWE Top 25 table in Section 1:

| CWE ID | Weakness | Ghoststrike Test Area |
|--------|----------|-----------------------|
| CWE-269 | Improper Privilege Management | Vertical privilege escalation (authenticated scanning) |
| CWE-284 | Improper Access Control | Authenticated endpoint access control |
| CWE-502 | Deserialization of Untrusted Data | Dependency vulnerability detection (SCA) |
| CWE-639 | Authorization Bypass Through User-Controlled Key | Horizontal escalation / IDOR |
| CWE-918 | Server-Side Request Forgery (SSRF) | SSRF probe module |
| CWE-1104 | Use of Unmaintained Third-Party Components | Outdated dependency detection (SCA) |

---

## ATT&CK Additions Summary

The following techniques should be appended to the ATT&CK table in Section 1:

| ATT&CK Technique | Name | Tactic | Ghoststrike Test Area |
|------------------|------|--------|-----------------------|
| T1078 | Valid Accounts | Privilege Escalation | Authenticated role testing |
| T1550 | Use Alternate Authentication Material | Defense Evasion | Token reuse after logout/expiry |

---

*Generated from residual gap analysis after Ghoststrike v2 compliance update. Covers the four remaining items from the original Formind methodology comparison: authenticated multi-role scanning, SCA/dependency scanning, OWASP API Security Top 10:2023, and Jira/ticketing integration.*
