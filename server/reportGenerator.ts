/**
 * Report Generator — produces comprehensive security reports from scan data.
 * Generates Markdown, JSON, and executive summary content.
 * Structure aligned with commercial penetration test deliverables (scope, impact, evidence, glossary).
 */

import { ScanFinding, Scan, Target } from "../drizzle/schema";
import { getIso27001ControlTitle, deriveApiSecurityCategory, type BusinessImpact, type AttackTechnique, type ApiSecurityMapping } from "./findingEnrichment";
import type { AttackScenario, TrendSummary, ScanAuthMeta, ToolAuthCapability } from "./scanEngine";
import { getToolAuthCapabilities } from "./scanEngine";

export interface ReportData {
  scan: Scan;
  target: Target;
  findings: ScanFinding[];
  generatedAt: Date;
}

const REPORT_VERSION = "1.1";

/** Derive a letter grade from the numeric security score. */
export function securityGrade(score: number): { grade: string; label: string } {
  if (score >= 90) return { grade: "A", label: "Excellent" };
  if (score >= 80) return { grade: "B", label: "Good" };
  if (score >= 70) return { grade: "C", label: "Adequate" };
  if (score >= 55) return { grade: "D", label: "Below Average" };
  return { grade: "F", label: "Critical" };
}

function severityBadge(severity: string): string {
  const badges: Record<string, string> = {
    critical: "🔴 CRITICAL",
    high: "🟠 HIGH",
    medium: "🟡 MEDIUM",
    low: "🔵 LOW",
    info: "⚪ INFO",
  };
  return badges[severity] || severity.toUpperCase();
}

function riskColor(score: number): string {
  if (score < 40) return "CRITICAL RISK";
  if (score < 60) return "HIGH RISK";
  if (score < 75) return "MEDIUM RISK";
  if (score < 90) return "LOW RISK";
  return "MINIMAL RISK";
}

/** Derive business impact text from finding category/severity for report readability. */
function impactFromCategory(category: string, severity: string): string {
  const impactByCategory: Record<string, string> = {
    "SQL Injection": "If exploited, an attacker could read, modify, or delete database content; escalate to full system compromise; or exfiltrate sensitive data. May result in data breach and regulatory exposure.",
    "XSS": "If exploited, an attacker could steal session cookies or credentials, perform actions as the victim, or deface the application. May lead to account takeover and data exposure.",
    "Cross-Site Scripting": "If exploited, an attacker could steal session cookies or credentials, perform actions as the victim, or deface the application. May lead to account takeover and data exposure.",
    "Headers": "Weak or missing security headers increase the risk of clickjacking, MIME sniffing attacks, or protocol downgrade. May facilitate other attacks.",
    "Security Headers": "Weak or missing security headers increase the risk of clickjacking, MIME sniffing attacks, or protocol downgrade. May facilitate other attacks.",
    "Authentication": "Weak authentication controls may allow brute force, account enumeration, or session abuse. Could lead to unauthorized access and account compromise.",
    "Auth": "Weak authentication controls may allow brute force, account enumeration, or session abuse. Could lead to unauthorized access and account compromise.",
    "CORS": "Permissive CORS may allow malicious sites to make authenticated requests to the application on behalf of users. Could lead to data theft or privilege abuse.",
    "Recon": "Exposed sensitive files or paths can reveal configuration, credentials, or internal structure. May enable further attacks or compliance issues.",
    "Information Disclosure": "Exposed sensitive files or paths can reveal configuration, credentials, or internal structure. May enable further attacks or compliance issues.",
    "Traversal": "Path traversal could allow read access to server files (e.g. config, source). May lead to credential theft and system compromise.",
    "Path Traversal": "Path traversal could allow read access to server files (e.g. config, source). May lead to credential theft and system compromise.",
    "Config": "Dangerous HTTP methods or misconfigurations may allow unintended modifications or information disclosure. Could facilitate abuse or denial of service.",
    "Security Misconfiguration": "Dangerous HTTP methods or misconfigurations may allow unintended modifications or information disclosure. Could facilitate abuse or denial of service.",
    "Nikto": "Server misconfigurations or outdated components may expose known vulnerabilities. Could lead to compromise or compliance failures.",
    "Nuclei": "Template-matched issues (CVEs, misconfigurations) may be exploitable. Impact depends on the specific finding.",
    "OWASP ZAP": "DAST-identified issues may indicate vulnerabilities or misconfigurations. Impact depends on the specific finding.",
    "Wapiti": "Scanner-identified issues may indicate vulnerabilities. Impact depends on the specific finding.",
    "TLS": "Weak TLS configuration may allow traffic interception, man-in-the-middle attacks, or protocol downgrade. Could expose sensitive data in transit.",
    "Business Logic": "Business logic flaws may allow privilege escalation, workflow bypass, debug information exposure, or CSRF attacks. Impact depends on the specific finding.",
    "GraphQL": "GraphQL misconfigurations may expose the full API schema, enable denial-of-service, or allow injection attacks through resolver arguments.",
    "Connectivity": "Connectivity or availability issues observed during testing; may affect assessment coverage.",
    "Tool Availability": "Informational; no direct security impact.",
  };
  return impactByCategory[category] ?? (severity === "critical" || severity === "high"
    ? "Exploitation could compromise confidentiality, integrity, or availability. Recommend remediation based on context."
    : "Lower risk; address as part of routine hardening.");
}

export function generateMarkdownReport(data: ReportData): string {
  const { scan, target, findings, generatedAt } = data;
  const score = scan.securityScore ?? 0;
  const riskLabel = riskColor(score);

  const bySeverity = {
    critical: findings.filter((f) => f.severity === "critical"),
    high: findings.filter((f) => f.severity === "high"),
    medium: findings.filter((f) => f.severity === "medium"),
    low: findings.filter((f) => f.severity === "low"),
    info: findings.filter((f) => f.severity === "info"),
  };

  const authMeta = (scan as any).authMeta as ScanAuthMeta | null;
  const isAuthenticated = authMeta?.authMode === "authenticated" || (scan as any).authMode === "authenticated";
  const authModeValue = isAuthenticated ? "authenticated" : "unauthenticated";

  const lines: string[] = [];

  // ── Auth Mode Banner ──
  if (isAuthenticated) {
    lines.push(`> 🟢 **AUTHENTICATED SCAN** — This assessment was performed with valid credentials, covering post-login application surfaces.`);
  } else {
    lines.push(`> 🟠 **UNAUTHENTICATED SCAN** — This assessment was performed without credentials, covering the external attack surface only.`);
  }
  lines.push(``);

  // ── Title & Document Control ──
  lines.push(`# Penetration Test Report`);
  lines.push(``);
  lines.push(`| Document | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Report version | ${REPORT_VERSION} |`);
  lines.push(`| Generated | ${generatedAt.toUTCString()} |`);
  lines.push(`| Scan ID | ${scan.id} |`);
  lines.push(`| Target | ${target.name} — ${target.url} |`);
  lines.push(`| Authentication Mode | **${isAuthenticated ? "Authenticated" : "Unauthenticated"}** |`);
  if (isAuthenticated && authMeta) {
    if (authMeta.authMethod) lines.push(`| Authentication Method | ${authMeta.authMethod.replace(/-/g, " ")} |`);
    if (authMeta.authRole) lines.push(`| Authenticated User / Role | ${authMeta.authRole} |`);
  }
  lines.push(`| Triggered by | ${scan.triggeredBy === "schedule" ? "Scheduled" : "Manual"} |`);
  lines.push(`| Duration | ${scan.startedAt && scan.completedAt ? Math.round((scan.completedAt.getTime() - scan.startedAt.getTime()) / 1000) + "s" : "N/A"} |`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Scope of Work ──
  const tools = (scan.tools || "").split(",").map((t) => t.trim());
  lines.push(`## 1. Scope of Work`);
  lines.push(``);
  lines.push(`### In scope`);
  lines.push(`- **Target:** ${target.name} (${target.url})`);
  lines.push(`- **Assessment type:** Automated penetration test (DAST / vulnerability scanning)`);
  lines.push(`- **Test domains:** ${tools.map((t) => t.toUpperCase()).join(", ")}`);
  lines.push(`- **Scan mode:** ${scan.scanMode ?? "light"}`);
  lines.push(`- **Authentication mode:** ${isAuthenticated ? "Authenticated" : "Unauthenticated"}`);
  if (isAuthenticated) {
    lines.push(`- **Coverage depth:** Full application surface (post-login)`);
    if (authMeta?.authMethod) lines.push(`- **Auth method:** ${authMeta.authMethod.replace(/-/g, " ")}`);
    if (authMeta?.authRole) lines.push(`- **Authenticated as:** ${authMeta.authRole}`);
    if (authMeta?.loginUrl) lines.push(`- **Login endpoint:** ${authMeta.loginUrl}`);
  } else {
    lines.push(`- **Coverage depth:** External surface only`);
  }
  lines.push(``);
  lines.push(`### Out of scope`);
  lines.push(`- Manual penetration testing, social engineering, and physical security`);
  lines.push(`- Code review (SAST) or dependency audit unless run separately`);
  lines.push(`- Testing of systems or endpoints not explicitly included as the target URL`);
  if (!isAuthenticated) {
    lines.push(`- Post-login application surfaces (no credentials were provided for this scan)`);
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Executive Summary (non-technical managerial synthesis) ──
  const { grade, label: gradeLabel } = securityGrade(score);
  lines.push(`## 2. Executive Summary`);
  lines.push(``);
  lines.push(`> **For decision-makers:** This section provides a non-technical overview of the security assessment results.`);
  lines.push(``);
  lines.push(`### Security Grade`);
  lines.push(``);
  const gradeEmoji = grade === "A" ? "🟢" : grade === "B" ? "🔵" : grade === "C" ? "🟡" : grade === "D" ? "🟠" : "🔴";
  lines.push(`${gradeEmoji} **Grade ${grade}** — ${gradeLabel} (${score}/100)`);
  lines.push(``);

  lines.push(`This report documents the results of an automated penetration test performed against **${target.name}** (${target.url}). The test was conducted using the Ghoststrike automated security assessment platform, aligned with industry-standard frameworks including OWASP Top 10:2021, PTES, NIST SP 800-115, CVSSv3.1, MITRE ATT&CK, and ISO 27001.`);
  lines.push(``);

  // Coverage depth indicator
  if (isAuthenticated) {
    const postAuthCount = findings.filter((f) => (f as any).authContext === "post-auth").length;
    const preAuthCount = findings.filter((f) => (f as any).authContext === "pre-auth").length;
    lines.push(`### Coverage Depth`);
    lines.push(``);
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Coverage | **Full application surface (post-login)** |`);
    if (authMeta?.authMethod) lines.push(`| Auth Method | ${authMeta.authMethod.replace(/-/g, " ")} |`);
    if (authMeta?.authRole) lines.push(`| Authenticated As | ${authMeta.authRole} |`);
    lines.push(`| Pre-authentication findings | ${preAuthCount} |`);
    lines.push(`| Post-authentication findings | ${postAuthCount} |`);
    lines.push(``);
    if (postAuthCount === 0 && findings.length > 0) {
      lines.push(`> ⚠️ **Warning:** Authenticated scan produced no additional findings beyond unauthenticated baseline — verify credentials were valid and session was maintained throughout the scan.`);
      lines.push(``);
    }
  } else {
    lines.push(`### Coverage Depth`);
    lines.push(``);
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Coverage | **External surface only** |`);
    lines.push(`| Note | Post-login application surfaces were not tested |`);
    lines.push(``);
  }

  // Top 3 risks in plain English
  const critHigh = [...bySeverity.critical, ...bySeverity.high];
  if (critHigh.length > 0) {
    lines.push(`### Top Risks`);
    lines.push(``);
    const topRisks = critHigh.slice(0, 3);
    topRisks.forEach((f, i) => {
      const impact = impactFromCategory(f.category, f.severity);
      const shortImpact = impact.split(".")[0];
      lines.push(`${i + 1}. **${f.title}** — ${shortImpact}.`);
    });
    lines.push(``);
    lines.push(`**Business risk:** These findings may expose the organisation to data breach, regulatory penalties (e.g. GDPR, PCI DSS), or service compromise. Addressing them should be the immediate priority.`);
    lines.push(``);
  }

  // Immediate actions (P1 items)
  const p1Items = findings.filter((f) => (f as any).remediationPriority === "P1");
  if (p1Items.length > 0) {
    lines.push(`### Recommended Immediate Actions`);
    lines.push(``);
    p1Items.slice(0, 5).forEach((f, i) => {
      lines.push(`${i + 1}. ${f.recommendation || `Remediate: ${f.title}`}`);
    });
    lines.push(``);
  }

  // Positive findings
  const positiveFindings: string[] = [];
  const cats = new Set(findings.map((f) => f.category));
  if (!cats.has("SQL Injection") && tools.includes("sqli")) positiveFindings.push("No SQL injection vulnerabilities detected");
  if (!cats.has("Cross-Site Scripting") && tools.includes("xss")) positiveFindings.push("No cross-site scripting vulnerabilities detected");
  if (!cats.has("Path Traversal") && tools.includes("traversal")) positiveFindings.push("No directory traversal vulnerabilities detected");
  if (!cats.has("TLS") && tools.includes("tls")) positiveFindings.push("SSL/TLS configuration is secure");
  const headerFindings = bySeverity.critical.filter((f) => f.category === "Security Headers").length + bySeverity.high.filter((f) => f.category === "Security Headers").length;
  if (headerFindings === 0 && tools.includes("headers")) positiveFindings.push("Security headers are reasonably well-configured");
  if (positiveFindings.length > 0) {
    lines.push(`### What Is Working Well`);
    lines.push(``);
    positiveFindings.forEach((p) => lines.push(`- ✅ ${p}`));
    lines.push(``);
  }

  lines.push(`### Overall Security Posture`);
  lines.push(``);
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Security Grade | **${grade}** (${gradeLabel}) |`);
  lines.push(`| Security Score | **${score}/100** |`);
  lines.push(`| Risk Level | **${riskLabel}** |`);
  lines.push(`| Total Findings | **${findings.length}** |`);
  lines.push(`| Critical | ${bySeverity.critical.length} |`);
  lines.push(`| High | ${bySeverity.high.length} |`);
  lines.push(`| Medium | ${bySeverity.medium.length} |`);
  lines.push(`| Low | ${bySeverity.low.length} |`);
  lines.push(`| Informational | ${bySeverity.info.length} |`);
  lines.push(``);
  // Severity distribution (text bar)
  const maxCount = Math.max(1, ...Object.values(bySeverity).map((a) => a.length));
  const bar = (n: number) => "█".repeat(Math.round((n / maxCount) * 6)) || "▌";
  lines.push(`**Severity distribution:**`);
  lines.push(`- Critical: ${bar(bySeverity.critical.length)} ${bySeverity.critical.length}`);
  lines.push(`- High:    ${bar(bySeverity.high.length)} ${bySeverity.high.length}`);
  lines.push(`- Medium:  ${bar(bySeverity.medium.length)} ${bySeverity.medium.length}`);
  lines.push(`- Low:     ${bar(bySeverity.low.length)} ${bySeverity.low.length}`);
  lines.push(`- Info:    ${bar(bySeverity.info.length)} ${bySeverity.info.length}`);
  lines.push(``);

  const riskEmoji = score < 40 ? "🔴" : score < 60 ? "🟠" : score < 75 ? "🟡" : score < 90 ? "🔵" : "🟢";
  lines.push(`${riskEmoji} **${riskLabel}** — ${score < 60 ? "Immediate action required to address critical and high severity vulnerabilities." : score < 80 ? "Security improvements recommended to address identified vulnerabilities." : "Good security posture. Continue monitoring and address remaining findings."}`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Test Coverage ──
  lines.push(`## 3. Test Coverage`);
  lines.push(``);
  lines.push(`The following security domains were assessed during this engagement:`);
  lines.push(``);
  const toolDescriptions: Record<string, string> = {
    headers: "HTTP Security Headers — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
    auth: "Authentication Security — Brute force protection, account enumeration, session management",
    sqli: "SQL Injection — Parameterised query validation, input sanitisation, error handling",
    xss: "Cross-Site Scripting — Reflected, stored, and DOM-based XSS vectors",
    recon: "Intelligence Gathering — Sensitive file exposure, technology fingerprinting, information disclosure",
    nikto: "Nikto Web Server Scanner — Server misconfigurations, outdated software, default files",
    nuclei: "Nuclei Template Scanning — CVE detection, misconfiguration checks, exposure detection",
    zap: "OWASP ZAP DAST — Dynamic application security testing baseline scan",
    tls: "SSL/TLS Analysis — Certificate validation, protocol version, cipher suite strength, optional testssl.sh deep analysis",
    logic: "Business Logic Tests — Debug endpoint detection, CSRF validation, mass assignment, stack trace exposure",
    graphql: "GraphQL Security — Endpoint detection, introspection, batch query abuse, injection testing",
    "auth-roles": "Authenticated Multi-Role Scanning — Vertical/horizontal privilege escalation, IDOR, session handling",
    sca: "Dependency / SCA Scanning — Vulnerable dependency detection via OSV-Scanner or Trivy",
    ssrf: "SSRF Probe — Server-Side Request Forgery testing via URL/redirect/callback parameter injection",
    "ai-prompt": "AI Prompt Injection — Jailbreak prompt detection, guardrail bypass, toxicity filter obfuscation (PEN-27)",
    "secret-leak": "Secret Exposure — Client secret and credential leakage in API GET responses (PEN-33)",
    "url-norm": "URL Normalisation Bypass — Percent-encoding, dot-segments, double-slashes, hostname tricks to bypass ACLs (PEN-42)",
    "http-client": "Insecure HTTP Client — TLS trustAll, verifyHost(false), HTTP/2 cleartext upgrade detection (PEN-52)",
    jwt: "JWT Security — Algorithm confusion (alg:none), expired token acceptance, weak HMAC signing detection",
    "cookie-flags": "Cookie Security — Secure, HttpOnly, SameSite flag validation on session cookies",
    smuggling: "HTTP Request Smuggling — CL.TE and TE.CL desync detection via timing and differential response analysis",
    crlf: "CRLF Injection — Header injection via CR/LF characters in URL parameters (response splitting, cache poisoning)",
    redirect: "Open Redirect — Redirect-to-external-domain detection on login, OAuth, and callback endpoints",
    "proto-pollution": "Prototype Pollution — __proto__ and constructor.prototype injection in JSON API endpoints",
  };
  for (const tool of tools) {
    lines.push(`- **${tool.toUpperCase()}**: ${toolDescriptions[tool] || tool}`);
  }
  lines.push(``);

  // Auth capability matrix
  if (isAuthenticated) {
    const capabilities = getToolAuthCapabilities(tools);
    lines.push(`### Tool Authentication Capability`);
    lines.push(``);
    lines.push(`| Tool | Auth Support | Note |`);
    lines.push(`|------|-------------|------|`);
    const supportBadge = (s: string) => s === "full" ? "✅ Full" : s === "limited" ? "⚠️ Limited" : "❌ None";
    for (const cap of capabilities) {
      lines.push(`| ${cap.tool.toUpperCase()} | ${supportBadge(cap.authSupport)} | ${cap.note} |`);
    }
    lines.push(``);
    const gaps = capabilities.filter((c) => c.authSupport !== "full");
    if (gaps.length > 0) {
      lines.push(`> **Coverage gaps:** ${gaps.map((g) => g.tool.toUpperCase()).join(", ")} ${gaps.length === 1 ? "does" : "do"} not fully support authenticated scanning. Findings from ${gaps.length === 1 ? "this tool" : "these tools"} may not differ between authenticated and unauthenticated scans.`);
      lines.push(``);
    }
  }

  lines.push(`---`);
  lines.push(``);

  // ── Findings summary table ──
  lines.push(`## 4. Findings Summary`);
  lines.push(``);

  if (findings.length === 0) {
    lines.push(`✅ **No vulnerabilities detected.** The target passed all security checks for the selected test categories.`);
  } else {
    if (isAuthenticated) {
      lines.push(`| # | Title | Severity | CVSS | Priority | Category | Auth Context | Status |`);
      lines.push(`|---|-------|----------|------|----------|----------|-------------|--------|`);
    } else {
      lines.push(`| # | Title | Severity | CVSS | Priority | Category | Status |`);
      lines.push(`|---|-------|----------|------|----------|----------|--------|`);
    }
    let idx = 1;
    for (const [sev] of [["critical"], ["high"], ["medium"], ["low"], ["info"]] as const) {
      for (const f of bySeverity[sev]) {
        const title = f.title.length > 55 ? f.title.substring(0, 52) + "..." : f.title;
        const cvss = f.cvssScore ? String(Number(f.cvssScore).toFixed(1)) : "—";
        const priority = (f as any).remediationPriority ?? "—";
        const authCtx = (f as any).authContext === "post-auth" ? "🔐 Post-auth" : (f as any).authContext === "pre-auth" ? "🌐 Pre-auth" : "—";
        if (isAuthenticated) {
          lines.push(`| ${idx++} | ${title} | ${severityBadge(f.severity)} | ${cvss} | ${priority} | ${f.category} | ${authCtx} | ${(f.status ?? "open").toUpperCase()} |`);
        } else {
          lines.push(`| ${idx++} | ${title} | ${severityBadge(f.severity)} | ${cvss} | ${priority} | ${f.category} | ${(f.status ?? "open").toUpperCase()} |`);
        }
      }
    }
    lines.push(``);
    lines.push(`---`);
    lines.push(``);

    // ── Detailed Findings ──
    lines.push(`## 5. Detailed Findings`);
    lines.push(``);

    for (const [sev, label] of [
      ["critical", "Critical Severity"],
      ["high", "High Severity"],
      ["medium", "Medium Severity"],
      ["low", "Low Severity"],
      ["info", "Informational"],
    ] as const) {
      const group = bySeverity[sev];
      if (group.length === 0) continue;

      lines.push(`### ${severityBadge(sev)} — ${label} (${group.length})`);
      lines.push(``);

      for (const f of group) {
        lines.push(`#### ${f.title}`);
        lines.push(``);
        lines.push(`| Field | Value |`);
        lines.push(`|-------|-------|`);
        lines.push(`| Category | ${f.category} |`);
        lines.push(`| Severity | ${severityBadge(f.severity)} |`);
        // Auth-scanning context from evidence
        const authContextMatch = f.evidence?.match(/^\[Auth Context\] (.+?)$/m);
        if (authContextMatch) {
          const parts = authContextMatch[1].split(" | ");
          for (const part of parts) {
            const [label2, ...val] = part.split(": ");
            if (label2 && val.length) lines.push(`| ${label2} | ${val.join(": ")} |`);
          }
        }
        if (f.cvssScore && f.cvssVector) {
          const score = Number(f.cvssScore).toFixed(1);
          lines.push(`| CVSSv3.1 | **${score}** — \`${f.cvssVector}\` |`);
        }
        if (f.cweId) lines.push(`| CWE | [${f.cweId}](https://cwe.mitre.org/data/definitions/${f.cweId.replace("CWE-", "")}.html) |`);
        if (f.owaspCategory) lines.push(`| OWASP | ${f.owaspCategory} |`);
        const techniques = f.attackTechniques as AttackTechnique[] | null;
        if (techniques && techniques.length > 0) {
          const techStr = techniques.map((t) => `[${t.techniqueId}](https://attack.mitre.org/techniques/${t.techniqueId}/) ${t.techniqueName} (${t.tactic})`).join(", ");
          lines.push(`| MITRE ATT&CK | ${techStr} |`);
        }
        const isoControls = f.iso27001Controls as string[] | null;
        if (isoControls && isoControls.length > 0) {
          lines.push(`| ISO 27001 | ${isoControls.map((c) => `${c} (${getIso27001ControlTitle(c)})`).join(", ")} |`);
        }
        const apiCat = deriveApiSecurityCategory(f.category, f.cweId);
        if (apiCat) {
          lines.push(`| OWASP API | [${apiCat.id}](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) ${apiCat.name} |`);
        }
        if ((f as any).remediationPriority) lines.push(`| Priority | **${(f as any).remediationPriority}** |`);
        if ((f as any).remediationComplexity) lines.push(`| Remediation Complexity | ${(f as any).remediationComplexity} |`);
        lines.push(`| Status | ${f.status?.toUpperCase() || "OPEN"} |`);
        lines.push(``);
        if (f.description) {
          lines.push(`**Description:** ${f.description}`);
          lines.push(``);
        }
        lines.push(`**Impact:** ${impactFromCategory(f.category, f.severity)}`);
        lines.push(``);
        const bizImpact = f.businessImpact as BusinessImpact | null;
        if (bizImpact) {
          lines.push(`**Business Impact Assessment:**`);
          lines.push(`| Dimension | Rating |`);
          lines.push(`|-----------|--------|`);
          lines.push(`| Financial | ${bizImpact.financial} |`);
          lines.push(`| Operational | ${bizImpact.operational} |`);
          lines.push(`| Reputational | ${bizImpact.reputational} |`);
          lines.push(`| Legal | ${bizImpact.legal} |`);
          lines.push(``);
          lines.push(`*${bizImpact.rationale}*`);
          lines.push(``);
        }
        if (f.evidence) {
          lines.push(`**Evidence:**`);
          lines.push(`\`\`\``);
          lines.push(f.evidence.length > 3000 ? f.evidence.substring(0, 3000) + "\n[... truncated for length ...]" : f.evidence);
          lines.push(`\`\`\``);
          lines.push(``);
        }
        if (f.recommendation) {
          lines.push(`**Recommendation:** ${f.recommendation}`);
          lines.push(``);
        }
        const poc = f.poc as { curlCommand?: string; requestRaw?: string; responseSnippet?: string; reproductionSteps?: string[] } | null;
        if (poc) {
          lines.push(`**Proof of Concept:**`);
          lines.push(``);
          if (poc.curlCommand) {
            lines.push(`*curl command:*`);
            lines.push(`\`\`\`bash`);
            lines.push(poc.curlCommand);
            lines.push(`\`\`\``);
            lines.push(``);
          }
          if (poc.requestRaw) {
            lines.push(`*Raw HTTP request:*`);
            lines.push(`\`\`\``);
            lines.push(poc.requestRaw.substring(0, 1000));
            lines.push(`\`\`\``);
            lines.push(``);
          }
          if (poc.responseSnippet) {
            lines.push(`*Response snippet:*`);
            lines.push(`\`\`\``);
            lines.push(poc.responseSnippet.substring(0, 500));
            lines.push(`\`\`\``);
            lines.push(``);
          }
          if (poc.reproductionSteps && poc.reproductionSteps.length > 0) {
            lines.push(`*Reproduction steps:*`);
            poc.reproductionSteps.forEach((s) => lines.push(`- ${s}`));
            lines.push(``);
          }
        }
        lines.push(`---`);
        lines.push(``);
      }
    }
  }

  // ── Remediation Action Plan ──
  lines.push(`## 6. Remediation Action Plan`);
  lines.push(``);

  const actionable = findings
    .filter((f) => (f as any).remediationPriority && f.severity !== "info")
    .sort((a, b) => {
      const order: Record<string, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };
      return (order[(a as any).remediationPriority] ?? 4) - (order[(b as any).remediationPriority] ?? 4);
    });

  if (actionable.length > 0) {
    lines.push(`| # | Title | CVSS | Priority | Complexity | Timeframe |`);
    lines.push(`|---|-------|------|----------|------------|-----------|`);
    const timeframes: Record<string, string> = { P1: "48 hours", P2: "2 weeks", P3: "Next release", P4: "Backlog" };
    actionable.forEach((f, i) => {
      const cvss = f.cvssScore ? Number(f.cvssScore).toFixed(1) : "—";
      const pri = (f as any).remediationPriority ?? "—";
      const cmplx = (f as any).remediationComplexity ?? "—";
      const title = f.title.length > 50 ? f.title.substring(0, 47) + "..." : f.title;
      lines.push(`| ${i + 1} | ${title} | ${cvss} | **${pri}** | ${cmplx} | ${timeframes[pri] ?? "—"} |`);
    });
    lines.push(``);
  }

  const criticalAndHigh = [...bySeverity.critical, ...bySeverity.high];
  if (criticalAndHigh.length > 0) {
    lines.push(`### Immediate Actions (P1 — Critical / High)`);
    lines.push(``);
    criticalAndHigh.forEach((f, i) => {
      lines.push(`${i + 1}. **${f.title}** — ${f.recommendation || "Remediate immediately."}`);
    });
    lines.push(``);
  }

  if (bySeverity.medium.length > 0) {
    lines.push(`### Short-Term Improvements (P2 — Medium)`);
    lines.push(``);
    bySeverity.medium.forEach((f, i) => {
      lines.push(`${i + 1}. **${f.title}** — ${f.recommendation || "Address within 2 weeks."}`);
    });
    lines.push(``);
  }

  lines.push(`### Long-Term Security Enhancements`);
  lines.push(``);
  lines.push(`1. **Continuous Security Testing** — Schedule weekly automated pen tests to detect new vulnerabilities as the application evolves.`);
  lines.push(`2. **Security Code Reviews** — Integrate SAST tools into the CI/CD pipeline to catch vulnerabilities at development time.`);
  lines.push(`3. **Dependency Management** — Regularly audit and update third-party dependencies using tools like \`npm audit\` or Snyk.`);
  lines.push(`4. **Security Awareness Training** — Ensure development teams are trained on OWASP Top 10 and secure coding practices.`);
  lines.push(`5. **Incident Response Planning** — Maintain and test an incident response plan for security breaches.`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Attack Scenarios ──
  const scenarios = scan.scenarios as AttackScenario[] | null;
  if (scenarios && scenarios.length > 0) {
    lines.push(`## 7. Attack Scenarios`);
    lines.push(``);
    lines.push(`The following attack scenarios were identified by chaining related findings into realistic attack narratives:`);
    lines.push(``);
    for (const s of scenarios) {
      lines.push(`### ${s.id}: ${s.title}`);
      lines.push(``);
      lines.push(`| Field | Value |`);
      lines.push(`|-------|-------|`);
      lines.push(`| Objective | ${s.objective} |`);
      lines.push(`| Likelihood | ${s.likelihood} |`);
      lines.push(`| Impact | ${s.impact} |`);
      lines.push(``);
      lines.push(`**Attack chain:**`);
      s.steps.forEach((step, i) => {
        lines.push(`${i + 1}. **${step.findingTitle}** — ${step.role}`);
      });
      lines.push(``);
    }
    lines.push(`---`);
    lines.push(``);
  }

  // ── Trend Analysis ──
  const trend = scan.trendSummary as TrendSummary | null;
  const nextSection = (scenarios && scenarios.length > 0) ? 8 : 7;
  const trendSection = nextSection + (trend ? 0 : -1);
  if (trend) {
    lines.push(`## ${nextSection}. Trend Analysis`);
    lines.push(``);
    lines.push(`Compared against previous scan #${trend.previousScanId} (${trend.previousScanDate}):`);
    lines.push(``);

    // Warn if scans used different auth modes
    const prevAuthMode = (trend as any).previousAuthMode;
    if (prevAuthMode && prevAuthMode !== authModeValue) {
      lines.push(`> ⚠️ **Different authentication modes:** This scan was **${authModeValue}** but the previous scan (#${trend.previousScanId}) was **${prevAuthMode}**. Differences in findings may reflect the changed authentication context rather than genuine vulnerability changes. This is not a like-for-like comparison.`);
      lines.push(``);
      if (isAuthenticated && prevAuthMode === "unauthenticated") {
        const newCount = trend.newFindings;
        const resolvedCount = trend.resolvedFindings;
        lines.push(`**Authenticated vs Unauthenticated comparison:**`);
        lines.push(`- **${newCount} findings unique to authenticated scan** — new attack surface visible only with valid credentials`);
        lines.push(`- **${trend.persistingFindings} findings common to both** — issues visible regardless of authentication state`);
        lines.push(`- **${resolvedCount} findings only in unauthenticated scan** — may be false positives or session-dependent behaviour`);
        lines.push(``);
      }
    }

    lines.push(`| Metric | Count |`);
    lines.push(`|--------|-------|`);
    lines.push(`| New findings | **${trend.newFindings}** |`);
    lines.push(`| Resolved findings | **${trend.resolvedFindings}** |`);
    lines.push(`| Persisting findings | **${trend.persistingFindings}** |`);
    lines.push(``);
    if (trend.newItems.length > 0) {
      lines.push(`**New findings:**`);
      trend.newItems.forEach((t) => lines.push(`- 🆕 ${t}`));
      lines.push(``);
    }
    if (trend.resolvedItems.length > 0) {
      lines.push(`**Resolved findings:**`);
      trend.resolvedItems.forEach((t) => lines.push(`- ✅ ${t}`));
      lines.push(``);
    }
    if (trend.persistingItems.length > 0) {
      lines.push(`**Persisting findings:**`);
      trend.persistingItems.forEach((t) => lines.push(`- ⚠️ ${t}`));
      lines.push(``);
    }
    lines.push(`---`);
    lines.push(``);
  }

  // ── Standards Compliance ──
  const complianceSection = (scenarios && scenarios.length > 0 ? 8 : 7) + (trend ? 1 : 0);
  lines.push(`## ${complianceSection}. Standards Compliance`);
  lines.push(``);
  lines.push(`| Framework | Coverage |`);
  lines.push(`|-----------|---------|`);
  lines.push(`| OWASP Top 10:2021 | A01, A02, A03, A05, A06, A07, A10 covered |`);
  lines.push(`| OWASP API Security Top 10:2023 | API1–API10 covered |`);
  lines.push(`| PTES (Penetration Testing Execution Standard) | Phases 2-5 |`);
  lines.push(`| NIST SP 800-115 | Discovery, Attack, Reporting phases |`);
  lines.push(`| CWE Top 25 | CWE-22, CWE-79, CWE-89, CWE-200, CWE-203, CWE-307, CWE-311, CWE-538, CWE-693, CWE-942, CWE-1021 |`);
  lines.push(`| CVSSv3.1 | Base score and vector string on every finding |`);
  lines.push(`| MITRE ATT&CK | Technique and tactic mapping per finding |`);
  lines.push(`| ISO/IEC 27001 | Annex A controls: A.9 Access Control, A.12 Operations Security, A.14 System Development, A.18 Compliance |`);
  lines.push(``);

  // OWASP API Security Top 10 coverage
  const apiSecurityCoverage = new Map<string, { mapping: ApiSecurityMapping; count: number }>();
  for (const f of findings) {
    const apiCat = deriveApiSecurityCategory(f.category, f.cweId);
    if (apiCat) {
      const existing = apiSecurityCoverage.get(apiCat.id);
      if (existing) existing.count++;
      else apiSecurityCoverage.set(apiCat.id, { mapping: apiCat, count: 1 });
    }
  }
  if (apiSecurityCoverage.size > 0) {
    lines.push(`### OWASP API Security Top 10:2023 Coverage`);
    lines.push(``);
    lines.push(`| Category | Name | Findings |`);
    lines.push(`|----------|------|----------|`);
    for (const [id, { mapping, count }] of Array.from(apiSecurityCoverage.entries()).sort((a, b) => a[0].localeCompare(b[0]))) {
      lines.push(`| ${id} | ${mapping.name} | ${count} |`);
    }
    lines.push(``);
  }

  // ISO 27001 control detail table
  const allIsoControls = new Set<string>();
  for (const f of findings) {
    const controls = f.iso27001Controls as string[] | null;
    if (controls) controls.forEach((c) => allIsoControls.add(c));
  }
  if (allIsoControls.size > 0) {
    lines.push(`### ISO 27001 Annex A Controls Covered`);
    lines.push(``);
    lines.push(`| Control | Title | Findings |`);
    lines.push(`|---------|-------|----------|`);
    for (const ctrl of Array.from(allIsoControls).sort()) {
      const count = findings.filter((f) => {
        const c = f.iso27001Controls as string[] | null;
        return c?.includes(ctrl);
      }).length;
      lines.push(`| ${ctrl} | ${getIso27001ControlTitle(ctrl)} | ${count} |`);
    }
    lines.push(``);
  }

  // ATT&CK coverage summary
  const allTechniques = new Map<string, { technique: AttackTechnique; count: number }>();
  for (const f of findings) {
    const techs = f.attackTechniques as AttackTechnique[] | null;
    if (techs) for (const t of techs) {
      const existing = allTechniques.get(t.techniqueId);
      if (existing) existing.count++;
      else allTechniques.set(t.techniqueId, { technique: t, count: 1 });
    }
  }
  if (allTechniques.size > 0) {
    lines.push(`### MITRE ATT&CK Coverage`);
    lines.push(``);
    lines.push(`| Technique | Name | Tactic | Findings |`);
    lines.push(`|-----------|------|--------|----------|`);
    allTechniques.forEach(({ technique: t, count }) => {
      lines.push(`| [${t.techniqueId}](https://attack.mitre.org/techniques/${t.techniqueId}/) | ${t.techniqueName} | ${t.tactic} | ${count} |`);
    });
    lines.push(``);
  }

  lines.push(`---`);
  lines.push(``);

  // ── Methodology ──
  const methodSection = complianceSection + 1;
  lines.push(`## ${methodSection}. Test Methodology`);
  lines.push(``);
  lines.push(`### Tools Used`);
  lines.push(`- PenTest Portal automated security scanner`);
  lines.push(`- Custom HTTP security header analyser`);
  lines.push(`- Authentication security tester`);
  lines.push(`- SQL injection probe suite`);
  lines.push(`- XSS vulnerability detector`);
  if (tools.includes("nikto")) lines.push(`- Nikto web server scanner`);
  if (tools.includes("nuclei")) lines.push(`- Nuclei template-based vulnerability scanner`);
  if (tools.includes("logic")) lines.push(`- Business logic test suite (debug detection, CSRF, mass assignment)`);
  if (tools.includes("graphql")) lines.push(`- GraphQL security scanner (introspection, batch abuse, injection)`);
  if (tools.includes("tls")) lines.push(`- SSL/TLS configuration analyser (native + testssl.sh)`);
  if (tools.includes("zap")) lines.push(`- OWASP ZAP dynamic application security testing`);
  lines.push(``);
  lines.push(`### Limitations`);
  lines.push(`- Automated testing cannot replace comprehensive manual penetration testing`);
  lines.push(`- Some vulnerabilities (e.g. business logic flaws) require human expertise to identify`);
  if (isAuthenticated) {
    lines.push(`- Tests were performed with provided credentials; coverage is limited to the permissions of the authenticated role`);
    lines.push(`- External tools (Nikto, Nuclei) have limited authenticated crawling — they may not discover post-login specific issues`);
  } else {
    lines.push(`- Tests were performed as an unauthenticated external user — post-login surfaces were not assessed`);
  }
  lines.push(`- Rate limiting and WAF rules may have prevented some test payloads from reaching the application`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Appendix: Glossary ──
  lines.push(`## Appendix A — Glossary`);
  lines.push(``);
  lines.push(`| Term | Definition |`);
  lines.push(`|------|------------|`);
  lines.push(`| **CWE** | Common Weakness Enumeration — a list of software and hardware weakness types (e.g. CWE-79 XSS, CWE-89 SQL injection). |`);
  lines.push(`| **CVE** | Common Vulnerabilities and Exposures — a catalogue of known security vulnerabilities. |`);
  lines.push(`| **DAST** | Dynamic Application Security Testing — testing a running application for vulnerabilities. |`);
  lines.push(`| **OWASP** | Open Web Application Security Project — community standards including the OWASP Top 10 list of web application risks. |`);
  lines.push(`| **OWASP API Top 10** | OWASP API Security Top 10:2023 — the most critical security risks specific to APIs (REST, GraphQL, SOAP). |`);
  lines.push(`| **PTES** | Penetration Testing Execution Standard — a methodology for conducting penetration tests. |`);
  lines.push(`| **NIST SP 800-115** | NIST guideline for technical security testing and assessment. |`);
  lines.push(`| **XSS** | Cross-Site Scripting — injection of client-side scripts into pages viewed by other users. |`);
  lines.push(`| **SQLi** | SQL Injection — injection of SQL commands via application input. |`);
  lines.push(`| **CORS** | Cross-Origin Resource Sharing — browser mechanism for cross-origin requests; misconfiguration can allow unauthorized access. |`);
  lines.push(`| **CVSS** | Common Vulnerability Scoring System — a standardised framework for rating the severity of security vulnerabilities (0.0–10.0). |`);
  lines.push(`| **MITRE ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge — a knowledge base of adversary behaviour and attack techniques. |`);
  lines.push(`| **ISO 27001** | International standard for information security management systems (ISMS), with Annex A security controls. |`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(`**Report version:** ${REPORT_VERSION} | **Generated:** ${generatedAt.toUTCString()}`);
  lines.push(`**Generated by:** PenTest Portal Automated Security Assessment Platform`);
  lines.push(`**Scan ID:** ${scan.id} | **Target:** ${target.url}`);

  return lines.join("\n");
}

export function generateExecutiveSummary(data: ReportData): string {
  const { scan, target, findings } = data;
  const score = scan.securityScore ?? 0;
  const { grade, label: gradeLabel } = securityGrade(score);
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;

  const authMeta = (scan as any).authMeta as ScanAuthMeta | null;
  const isAuth = authMeta?.authMode === "authenticated" || (scan as any).authMode === "authenticated";

  const parts: string[] = [];
  const modeLabel = isAuth ? "authenticated" : "unauthenticated";
  parts.push(`${modeLabel.charAt(0).toUpperCase() + modeLabel.slice(1)} security assessment of ${target.name} (${target.url}) completed with a grade of ${grade} (${gradeLabel}) — ${score}/100.`);
  if (isAuth) {
    parts.push(`Coverage: full application surface (post-login)${authMeta?.authRole ? ` as ${authMeta.authRole}` : ""}.`);
  } else {
    parts.push(`Coverage: external surface only.`);
  }
  parts.push(`${findings.length} finding(s) identified: ${critical} critical, ${high} high, ${medium} medium, ${low} low.`);

  if (isAuth) {
    const postAuthCount = findings.filter((f) => (f as any).authContext === "post-auth").length;
    if (postAuthCount === 0 && findings.length > 0) {
      parts.push("WARNING: Authenticated scan produced no additional findings beyond unauthenticated baseline — verify credentials were valid and session was maintained.");
    }
  }

  const critHigh = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  if (critHigh.length > 0) {
    const topRisks = critHigh.slice(0, 3).map((f) => f.title).join("; ");
    parts.push(`Top risks: ${topRisks}.`);
    parts.push("Immediate remediation required for critical and high severity issues.");
  } else if (score >= 80) {
    parts.push("The application demonstrates a strong security posture.");
  } else {
    parts.push("Security improvements are recommended.");
  }

  return parts.join(" ");
}

export function generateJSONReport(data: ReportData): object {
  const { scan, target, findings, generatedAt } = data;
  const tools = (scan.tools || "").split(",").map((t) => t.trim());
  const authMetaJson = (scan as any).authMeta as ScanAuthMeta | null;
  const isAuthJson = authMetaJson?.authMode === "authenticated" || (scan as any).authMode === "authenticated";
  const capabilities = getToolAuthCapabilities(tools);
  return {
    metadata: {
      reportVersion: REPORT_VERSION,
      generatedAt: generatedAt.toISOString(),
      scanId: scan.id,
      targetId: target.id,
    },
    scope: {
      target: { name: target.name, url: target.url },
      assessmentType: "Automated penetration test (DAST)",
      testDomains: tools,
      scanMode: scan.scanMode ?? "light",
      authMode: isAuthJson ? "authenticated" : "unauthenticated",
      coverageDepth: isAuthJson ? "Full application surface (post-login)" : "External surface only",
      authMeta: authMetaJson ?? null,
    },
    target: {
      name: target.name,
      url: target.url,
      description: target.description,
    },
    summary: {
      securityScore: scan.securityScore,
      securityGrade: securityGrade(scan.securityScore ?? 0),
      riskLevel: scan.riskLevel,
      status: scan.status,
      triggeredBy: scan.triggeredBy,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      totalFindings: findings.length,
      bySeverity: {
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
        low: findings.filter((f) => f.severity === "low").length,
        info: findings.filter((f) => f.severity === "info").length,
      },
    },
    findings: findings.map((f) => ({
      id: f.id,
      category: f.category,
      severity: f.severity,
      title: f.title,
      description: f.description,
      impact: impactFromCategory(f.category, f.severity),
      evidence: f.evidence,
      recommendation: f.recommendation,
      cweId: f.cweId,
      owaspCategory: f.owaspCategory,
      cvss: f.cvssScore ? {
        version: "3.1",
        vectorString: f.cvssVector,
        baseScore: Number(f.cvssScore),
        baseSeverity: Number(f.cvssScore) >= 9.0 ? "CRITICAL" : Number(f.cvssScore) >= 7.0 ? "HIGH" : Number(f.cvssScore) >= 4.0 ? "MEDIUM" : Number(f.cvssScore) > 0 ? "LOW" : "NONE",
      } : null,
      businessImpact: f.businessImpact ?? null,
      remediation: {
        description: f.recommendation,
        complexity: (f as any).remediationComplexity ?? null,
        priority: (f as any).remediationPriority ?? null,
        timeframe: (f as any).remediationPriority === "P1" ? "48 hours" : (f as any).remediationPriority === "P2" ? "2 weeks" : (f as any).remediationPriority === "P3" ? "Next release" : null,
      },
      attackTechniques: f.attackTechniques ?? null,
      iso27001Controls: f.iso27001Controls ?? null,
      apiSecurityCategory: deriveApiSecurityCategory(f.category, f.cweId),
      authContext: (() => {
        const m = f.evidence?.match(/^\[Auth Context\] (.+?)$/m);
        if (!m) return (f as any).authContext ? { mode: (f as any).authContext } : null;
        const obj: Record<string, string> = {};
        for (const part of m[1].split(" | ")) {
          const [k, ...v] = part.split(": ");
          if (k && v.length) obj[k.replace(/\s+/g, "").charAt(0).toLowerCase() + k.replace(/\s+/g, "").slice(1)] = v.join(": ");
        }
        if ((f as any).authContext) obj.mode = (f as any).authContext;
        return Object.keys(obj).length > 0 ? obj : null;
      })(),
      poc: f.poc ?? null,
      status: f.status,
      detectedAt: f.createdAt,
    })),
    scenarios: scan.scenarios ?? [],
    trend: scan.trendSummary ?? null,
    compliance: {
      frameworks: ["OWASP Top 10:2021", "OWASP API Security Top 10:2023", "PTES", "NIST SP 800-115", "CWE Top 25", "CVSSv3.1", "MITRE ATT&CK", "ISO/IEC 27001"],
      toolsUsed: tools,
      toolAuthCapabilities: capabilities.map((c) => ({ tool: c.tool, authSupport: c.authSupport, note: c.note })),
    },
  };
}
