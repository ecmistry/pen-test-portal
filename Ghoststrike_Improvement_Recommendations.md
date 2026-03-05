# Ghoststrike — Improvement Recommendations
> Derived from gap analysis against Formind's professional pentest methodology (Gravitee 4.8 & 4.9 engagement)

---

## Context

Ghoststrike is currently a strong automated scanning platform with solid OWASP/CWE/NIST coverage and clean report output. The following recommendations are prioritised to close the gap between automated scanning and professional whitebox penetration testing, making Ghoststrike more credible for enterprise security programmes.

---

## Priority 1 — Critical Gaps (Highest Value, Implement First)

### 1.1 CVSSv3 Scoring on Every Finding

**Gap:** Ghoststrike reports severity (e.g. High/Medium/Low) but does not output a CVSSv3 base score or vector string.

**Formind does:** Every vulnerability sheet includes a CVSSv3 base score, temporal score, attack vector, attack complexity, privileges required, user interaction, and AICT impact ratings (Availability, Integrity, Confidentiality, Traceability).

**Recommendation:**
- Implement CVSSv3.1 scoring for every finding using the standard vector components: `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`
- Calculate base score programmatically using the CVSS 3.1 specification formula
- Output the full vector string in reports: e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Add a temporal score component where exploit maturity is known
- Map severity bands to CVSS ranges: Critical (9.0–10.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9)
- Include a link to `https://www.first.org/cvss/specification-document` in report output
- Add a `cvss` field to the JSON finding schema:
```json
{
  "cvss": {
    "version": "3.1",
    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "baseScore": 9.8,
    "baseSeverity": "CRITICAL",
    "temporalScore": 8.5
  }
}
```

---

### 1.2 Business Impact Assessment per Finding

**Gap:** Ghoststrike findings describe the technical vulnerability but do not assess business risk.

**Formind does:** Each finding includes estimated impact across four business dimensions: Financial, Operational, Reputational, and Legal — each rated None/Low/Medium/High/Critical.

**Recommendation:**
- Add a `businessImpact` object to each finding in the JSON schema:
```json
{
  "businessImpact": {
    "financial": "Medium",
    "operational": "High",
    "reputational": "Low",
    "legal": "Medium",
    "rationale": "Exploiting this vulnerability could allow unauthorised access to customer data, triggering GDPR notification obligations."
  }
}
```
- Use rule-based inference to populate these fields automatically based on finding type:
  - SQL injection → High financial, High operational, High legal
  - Missing HSTS → Low financial, Low operational, Low legal
  - Account enumeration → Medium financial, Medium reputational
- Allow manual override in config for custom risk appetite settings
- Include a business impact summary table in the report output

---

### 1.3 Attack Scenario Narratives

**Gap:** Ghoststrike lists individual vulnerabilities in isolation. There is no chaining of findings into realistic attack scenarios.

**Formind does:** Reports include full attack scenario diagrams showing how an attacker moves from initial access through to a defined objective (e.g. data exfiltration, denial of service, account takeover), with each step referencing a specific vulnerability finding.

**Recommendation:**
- After scanning completes, run an attack chain analysis pass that attempts to link findings into scenarios
- Define scenario templates based on common chains:
  - `Account Enumeration` + `Brute Force` → Account Takeover
  - `CORS Misconfiguration` + `XSS` → Session Hijack
  - `SQL Injection` + `Sensitive Data Exposure` → Data Exfiltration
  - `Missing Auth` + `Directory Traversal` → Unauthorised File Access
- Output a `scenarios` array in the JSON report:
```json
{
  "scenarios": [
    {
      "id": "S-001",
      "title": "Unauthenticated Data Exfiltration",
      "objective": "Extract sensitive customer records",
      "steps": ["F-003", "F-007", "F-012"],
      "likelihood": "Medium",
      "impact": "High"
    }
  ]
}
```
- Render scenarios as a narrative section in the HTML/PDF report with a simple step diagram

---

### 1.4 Remediation Complexity & Priority Ratings

**Gap:** Ghoststrike provides remediation advice but does not rate the effort required to fix each finding.

**Formind does:** Each vulnerability sheet includes an estimated remediation complexity (Low/Medium/High) and a priority ranking (P1/P2/P3), enabling engineering teams to build a sequenced action plan.

**Recommendation:**
- Add `remediationComplexity` and `priority` fields to each finding
- Define complexity inference rules:
  - Header misconfigurations → Low complexity (config change)
  - CORS fixes → Low-Medium (config + code review)
  - SQL injection → Medium-High (code refactoring required)
  - Auth logic flaws → High (architectural change)
- Priority should be derived from CVSSv3 score + business impact:
  - P1: Critical/High CVSS + High business impact → fix within 48 hours
  - P2: Medium CVSS or High CVSS + Low business impact → fix within 2 weeks
  - P3: Low CVSS → fix in next scheduled release
- Output a prioritised action plan table in the report:

| ID | Title | Complexity | Priority | Owner |
|----|-------|------------|----------|-------|
| F-001 | SQL Injection on /api/users | Medium | P1 | Backend |
| F-002 | Missing HSTS Header | Low | P3 | Infra |

---

## Priority 2 — Methodology Enhancements

### 2.1 ATT&CK Framework Mapping

**Gap:** Ghoststrike maps to OWASP and CWE but not to MITRE ATT&CK.

**Formind does:** Uses Kill Chain and ATT&CK as methodological foundations alongside OWASP.

**Recommendation:**
- Add ATT&CK tactic and technique mapping to each finding where applicable
- Focus on the ATT&CK for Enterprise and ATT&CK for Web Application matrices
- Example mappings:
  - SQL Injection → T1190 (Exploit Public-Facing Application)
  - Credential Brute Force → T1110 (Brute Force)
  - SSRF → T1090 (Proxy) / T1083 (File and Directory Discovery)
  - XSS → T1185 (Browser Session Hijacking)
- Add `attackTechniques` array to finding JSON:
```json
{
  "attackTechniques": [
    {
      "techniqueId": "T1190",
      "techniqueName": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "url": "https://attack.mitre.org/techniques/T1190/"
    }
  ]
}
```
- Include an ATT&CK coverage heatmap in the report (similar to ATT&CK Navigator format)

---

### 2.2 Authenticated Scanning Support

**Gap:** Ghoststrike's auth module tests for brute-force and enumeration weaknesses but does not appear to support scanning as an authenticated user across multiple privilege levels.

**Formind does:** Tests resources and actions accessible without authentication, AND unauthorised actions for certain profiles — implying multi-role authenticated testing.

**Recommendation:**
- Add an `authProfiles` configuration block supporting multiple named accounts:
```json
{
  "authProfiles": [
    { "name": "anonymous", "type": "none" },
    { "name": "standard_user", "type": "bearer", "token": "..." },
    { "name": "admin", "type": "bearer", "token": "..." }
  ]
}
```
- For each authenticated profile, re-run the full scan suite
- Add a horizontal privilege escalation check: attempt to access `user_A` resources while authenticated as `user_B`
- Add a vertical privilege escalation check: attempt admin endpoints while authenticated as standard user
- Report findings with the profile context: `"discoveredAs": "standard_user", "exploitableAs": "standard_user", "accessLevel": "admin"`

---

### 2.3 Business Logic Test Templates

**Gap:** Ghoststrike does not test business logic vulnerabilities.

**Formind does:** Manually audits hijacking of endpoint call workflows, hijacking of client logic, activation of debug mode, and CSRF protections.

**Recommendation:**
- Add a `businessLogic` test module with configurable test cases:
  - **Workflow hijacking:** Allow the user to define a multi-step flow (e.g. `step1 → step2 → step3`); Ghoststrike attempts to skip steps or access later steps without completing earlier ones
  - **Debug mode detection:** Check for responses containing stack traces, debug headers (`X-Debug`, `X-Powered-By`, `Server`), verbose error messages, or endpoints matching patterns like `/debug`, `/actuator`, `/metrics`, `/__debug__`
  - **CSRF token validation:** For state-changing requests, verify that CSRF tokens are present, validated server-side, and not reusable
  - **Mass assignment detection:** Send additional unexpected fields in POST/PUT bodies and check if they are reflected in responses
- Define test cases in a YAML config file for extensibility

---

### 2.4 Dependency / SCA Scanning Integration

**Gap:** Ghoststrike has no Software Composition Analysis capability.

**Formind does:** Uses Snyk for dependency scanning and identifies vulnerable third-party components as a distinct finding category.

**Recommendation:**
- Add optional integration with Trivy or OSV-Scanner (both open source) for dependency scanning
- Accept a `package.json`, `pom.xml`, `go.mod`, `requirements.txt`, or `Gemfile.lock` as optional input
- Map vulnerable dependency findings to CVE IDs and CWE IDs
- Include dependency findings in the main report with the same severity/CVSS structure as other findings
- Add `"type": "dependency"` to the finding schema to distinguish from runtime findings

---

### 2.5 SSL/TLS Configuration Deep Analysis

**Gap:** Ghoststrike checks for HSTS enforcement but does not perform a full TLS configuration audit.

**Formind does:** Includes SSL certificate analysis as a distinct test category in both web and API attack phases.

**Recommendation:**
- Integrate with `testssl.sh` or implement equivalent checks natively:
  - Certificate validity, expiry, and chain completeness
  - Supported TLS versions (flag TLS 1.0 and 1.1 as findings)
  - Weak cipher suite detection (RC4, DES, 3DES, export ciphers)
  - Forward secrecy support
  - Certificate transparency log presence
  - OCSP stapling support
  - Mixed content detection
- Map TLS findings to CWE-326 (Inadequate Encryption Strength) and CWE-295 (Improper Certificate Validation)

---

## Priority 3 — Reporting Enhancements

### 3.1 Executive Summary Section

**Gap:** Ghoststrike reports are technically detailed but lack a non-technical summary for decision-makers.

**Formind does:** Every report includes a managerial synthesis that explains the overall security level (scored 1–5), the main risks and impacts, and what an attacker could realistically achieve.

**Recommendation:**
- Auto-generate an executive summary at the top of every report containing:
  - **Overall security score** (1–5 or A–F) derived from finding distribution
  - **Critical findings count** with one-line summaries
  - **Top 3 risks** in plain English (no jargon)
  - **Recommended immediate actions** (P1 items only)
  - **Positive findings** — what is working well (headers present, no SQLi found, etc.)
- Example narrative generation prompt for LLM-assisted summary (optional feature):
  > "Given these findings: [findings JSON], generate a 200-word executive summary suitable for a non-technical CISO. Highlight the most critical risks, their business impact, and the top 3 recommended actions."

---

### 3.2 Replay / Evidence Artifacts

**Gap:** Ghoststrike captures evidence (responses, screenshots where applicable) but does not produce structured proof-of-concept artifacts.

**Formind does:** Produces replay videos of the most critical vulnerabilities and structured evidence packs per finding.

**Recommendation:**
- For each confirmed finding, capture and store:
  - The exact HTTP request that triggered the vulnerability (raw format)
  - The response that confirms exploitability
  - A curl-equivalent command for manual reproduction
- Output a `poc` block in each finding:
```json
{
  "poc": {
    "curlCommand": "curl -X GET 'https://target.com/api/users?id=1 OR 1=1' -H 'Authorization: Bearer ...'",
    "requestRaw": "GET /api/users?id=1+OR+1%3D1 HTTP/1.1\nHost: target.com\n...",
    "responseSnippet": "admin@target.com, user@target.com, ...",
    "reproductionSteps": ["1. Send the request above", "2. Observe user data in response"]
  }
}
```
- Add a `--save-evidence` flag that writes request/response pairs to a structured directory

---

### 3.3 Compliance Mapping Expansion — ISO 27001 Full Annex A

**Gap:** Ghoststrike references ISO 27001 Control A.14 only.

**Recommendation:**
- Expand ISO 27001 mapping to full Annex A controls relevant to technical testing:
  - A.9 — Access Control (auth findings)
  - A.10 — Cryptography (TLS/HSTS findings)
  - A.12 — Operations Security (misconfiguration findings)
  - A.14 — System Acquisition, Development & Maintenance (injection/XSS findings)
  - A.18 — Compliance (GDPR/PCI DSS risk flags)
- Add ISO 27001 control references to the compliance table in reports

---

### 3.4 Trend Reporting Across Scans

**Gap:** Each Ghoststrike scan is independent with no historical comparison.

**Recommendation:**
- Add a local scan history store (SQLite or JSON file-based)
- On each scan, compare results against the previous scan of the same target:
  - **New findings** since last scan
  - **Resolved findings** (present before, gone now)
  - **Persisting findings** (unresolved across N scans)
- Generate a trend summary in the report:
  - "3 new findings since last scan on 2025-11-01"
  - "2 findings resolved since last scan"
  - "F-007 has been unresolved for 45 days"
- This closes the gap with Formind's retest phase — Ghoststrike can approximate retest verification automatically

---

## Priority 4 — Platform & Integration

### 4.1 JIRA / Ticketing Integration

**Gap:** Ghoststrike outputs reports but does not push findings into issue trackers.

**Formind does:** Has direct Jira access and reports vulnerabilities there in real time during the engagement.

**Recommendation:**
- Add a `--jira` output flag that creates Jira issues for each finding above a configurable severity threshold
- Map finding fields to Jira fields:
  - `title` → Issue Summary
  - `severity` → Priority
  - `description` + `remediation` → Description body
  - `cvss.baseScore` → Custom field
  - `owasp` + `cwe` → Labels
- Support Jira Cloud and Jira Data Center via API token auth
- Also add GitHub Issues and Linear as optional integrations
- Add a `integrations` block to the config schema:
```json
{
  "integrations": {
    "jira": {
      "enabled": true,
      "baseUrl": "https://your-org.atlassian.net",
      "projectKey": "SEC",
      "minSeverity": "Medium"
    }
  }
}
```

---

### 4.2 CI/CD Pipeline Mode

**Gap:** Ghoststrike does not have an explicit CI/CD-optimised mode with exit codes and threshold-based pass/fail.

**Recommendation:**
- Add a `--ci` flag that:
  - Suppresses interactive output, outputs only JSON and a summary line
  - Returns exit code `0` if no findings meet the threshold, `1` if findings exceed threshold
  - Accepts a `--fail-on` parameter: `--fail-on critical`, `--fail-on high`, `--fail-on cvss:7.0`
- Add a `.ghoststrike.yml` config file format for project-level defaults
- Publish a GitHub Actions workflow template and GitLab CI snippet in the documentation

---

### 4.3 GraphQL Support

**Gap:** Ghoststrike tests REST APIs but does not appear to handle GraphQL endpoints.

**Formind does:** Tests API-specific attack surfaces including endpoint enumeration and injection.

**Recommendation:**
- Add a `graphql` test module that:
  - Detects GraphQL endpoints automatically (`/graphql`, `/api/graphql`, `/__graphql`)
  - Attempts introspection queries to enumerate the schema
  - Tests for batch query abuse (sending 100+ operations in one request)
  - Tests for field-level injection (inject SQL/NoSQL payloads into GraphQL arguments)
  - Checks for disabled introspection as a positive security control
- Map GraphQL findings to OWASP API Security Top 10 (separate from OWASP Web Top 10):
  - API3:2023 Broken Object Property Level Authorization
  - API8:2023 Security Misconfiguration

---

## Summary Priority Matrix

| Recommendation | Impact | Effort | Priority |
|---|---|---|---|
| CVSSv3 Scoring | Very High | Medium | P1 |
| Business Impact Assessment | Very High | Low-Medium | P1 |
| Attack Scenario Chaining | High | High | P1 |
| Remediation Complexity & Priority | High | Low | P1 |
| ATT&CK Framework Mapping | High | Medium | P2 |
| Authenticated Multi-Role Scanning | Very High | High | P2 |
| Business Logic Test Templates | High | High | P2 |
| Dependency / SCA Scanning | High | Medium | P2 |
| TLS Deep Analysis | Medium | Medium | P2 |
| Executive Summary Auto-Generation | High | Medium | P3 |
| PoC / Evidence Artifacts | Medium | Low | P3 |
| ISO 27001 Full Annex A Mapping | Medium | Low | P3 |
| Trend Reporting | High | Medium | P3 |
| Jira / Ticketing Integration | High | Medium | P4 |
| CI/CD Pipeline Mode | High | Low | P4 |
| GraphQL Support | Medium | Medium | P4 |

---

## JSON Schema — Recommended Finding Structure

The following represents the target finding schema incorporating all recommendations above:

```json
{
  "id": "F-001",
  "type": "runtime",
  "title": "SQL Injection on /api/users",
  "description": "...",
  "owasp": "A03:2021",
  "cwe": "CWE-89",
  "cvss": {
    "version": "3.1",
    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "baseScore": 9.8,
    "baseSeverity": "CRITICAL",
    "temporalScore": 8.5
  },
  "attackTechniques": [
    {
      "techniqueId": "T1190",
      "techniqueName": "Exploit Public-Facing Application",
      "tactic": "Initial Access"
    }
  ],
  "businessImpact": {
    "financial": "High",
    "operational": "High",
    "reputational": "Medium",
    "legal": "High",
    "rationale": "Potential GDPR breach via customer data exfiltration."
  },
  "remediation": {
    "description": "Use parameterised queries...",
    "complexity": "Medium",
    "priority": "P1",
    "timeframe": "48 hours"
  },
  "poc": {
    "curlCommand": "curl -X GET 'https://target.com/api/users?id=1 OR 1=1'",
    "requestRaw": "...",
    "responseSnippet": "...",
    "reproductionSteps": ["..."]
  },
  "iso27001Controls": ["A.14.2.8"],
  "evidence": {
    "requestFile": "evidence/F-001-request.txt",
    "responseFile": "evidence/F-001-response.txt"
  }
}
```

---

*Generated from gap analysis against Formind penetration testing proposal (Gravitee 4.8 & 4.9, September 2025) and Ghoststrike COMPLIANCE_STANDARDS.md. Intended as a Cursor prompt reference document.*
