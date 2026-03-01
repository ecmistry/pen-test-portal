/**
 * Report Generator — produces comprehensive security reports from scan data.
 * Generates Markdown, JSON, and executive summary content.
 * Structure aligned with commercial penetration test deliverables (scope, impact, evidence, glossary).
 */

import { ScanFinding, Scan, Target } from "../drizzle/schema";

export interface ReportData {
  scan: Scan;
  target: Target;
  findings: ScanFinding[];
  generatedAt: Date;
}

const REPORT_VERSION = "1.0";

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

  const lines: string[] = [];

  // ── Title & Document Control ──
  lines.push(`# Penetration Test Report`);
  lines.push(``);
  lines.push(`| Document | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Report version | ${REPORT_VERSION} |`);
  lines.push(`| Generated | ${generatedAt.toUTCString()} |`);
  lines.push(`| Scan ID | ${scan.id} |`);
  lines.push(`| Target | ${target.name} — ${target.url} |`);
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
  lines.push(``);
  lines.push(`### Out of scope`);
  lines.push(`- Manual penetration testing, social engineering, and physical security`);
  lines.push(`- Code review (SAST) or dependency audit unless run separately`);
  lines.push(`- Testing of systems or endpoints not explicitly included as the target URL`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Executive Summary ──
  lines.push(`## 2. Executive Summary`);
  lines.push(``);
  lines.push(`This report documents the results of an automated penetration test performed against **${target.name}** (${target.url}). The test was conducted using the PenTest Portal automated security assessment platform, aligned with industry-standard frameworks including OWASP Top 10:2021, PTES (Penetration Testing Execution Standard), NIST SP 800-115, and CWE Top 25.`);
  lines.push(``);
  if (bySeverity.critical.length > 0 || bySeverity.high.length > 0) {
    lines.push(`**Business risk:** Critical and high severity findings may expose the organisation to data breach, regulatory penalties (e.g. GDPR, PCI DSS), or service compromise. Addressing these findings should be prioritised.`);
    lines.push(``);
  }
  lines.push(`### Overall Security Posture`);
  lines.push(``);
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
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
  };
  for (const tool of tools) {
    lines.push(`- **${tool.toUpperCase()}**: ${toolDescriptions[tool] || tool}`);
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Findings summary table ──
  lines.push(`## 4. Findings Summary`);
  lines.push(``);

  if (findings.length === 0) {
    lines.push(`✅ **No vulnerabilities detected.** The target passed all security checks for the selected test categories.`);
  } else {
    lines.push(`| # | Title | Severity | Category | Status |`);
    lines.push(`|---|-------|----------|----------|--------|`);
    let idx = 1;
    for (const [sev] of [["critical"], ["high"], ["medium"], ["low"], ["info"]] as const) {
      for (const f of bySeverity[sev]) {
        const title = f.title.length > 60 ? f.title.substring(0, 57) + "..." : f.title;
        lines.push(`| ${idx++} | ${title} | ${severityBadge(f.severity)} | ${f.category} | ${(f.status ?? "open").toUpperCase()} |`);
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
        if (f.cweId) lines.push(`| CWE | [${f.cweId}](https://cwe.mitre.org/data/definitions/${f.cweId.replace("CWE-", "")}.html) |`);
        if (f.owaspCategory) lines.push(`| OWASP | ${f.owaspCategory} |`);
        lines.push(`| Status | ${f.status?.toUpperCase() || "OPEN"} |`);
        lines.push(``);
        if (f.description) {
          lines.push(`**Description:** ${f.description}`);
          lines.push(``);
        }
        lines.push(`**Impact:** ${impactFromCategory(f.category, f.severity)}`);
        lines.push(``);
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
        lines.push(`---`);
        lines.push(``);
      }
    }
  }

  // ── Recommendations ──
  lines.push(`## 6. Recommendations`);
  lines.push(``);

  const criticalAndHigh = [...bySeverity.critical, ...bySeverity.high];
  if (criticalAndHigh.length > 0) {
    lines.push(`### Immediate Actions (Critical / High Priority)`);
    lines.push(``);
    criticalAndHigh.forEach((f, i) => {
      lines.push(`${i + 1}. **${f.title}** — ${f.recommendation || "Remediate immediately."}`);
    });
    lines.push(``);
  }

  if (bySeverity.medium.length > 0) {
    lines.push(`### Short-Term Improvements (Medium Priority)`);
    lines.push(``);
    bySeverity.medium.forEach((f, i) => {
      lines.push(`${i + 1}. **${f.title}** — ${f.recommendation || "Address within 30 days."}`);
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

  // ── Standards Compliance ──
  lines.push(`## 7. Standards Compliance`);
  lines.push(``);
  lines.push(`| Framework | Coverage |`);
  lines.push(`|-----------|---------|`);
  lines.push(`| OWASP Top 10:2021 | A01, A02, A03, A05, A07 covered |`);
  lines.push(`| PTES (Penetration Testing Execution Standard) | Phases 2-5 |`);
  lines.push(`| NIST SP 800-115 | Discovery, Attack, Reporting phases |`);
  lines.push(`| CWE Top 25 | CWE-79, CWE-89, CWE-307, CWE-693 |`);
  lines.push(`| ISO/IEC 27001 | A.14 System acquisition, development and maintenance |`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Methodology ──
  lines.push(`## 8. Test Methodology`);
  lines.push(``);
  lines.push(`### Tools Used`);
  lines.push(`- PenTest Portal automated security scanner`);
  lines.push(`- Custom HTTP security header analyser`);
  lines.push(`- Authentication security tester`);
  lines.push(`- SQL injection probe suite`);
  lines.push(`- XSS vulnerability detector`);
  if (tools.includes("nikto")) lines.push(`- Nikto web server scanner`);
  if (tools.includes("nuclei")) lines.push(`- Nuclei template-based vulnerability scanner`);
  if (tools.includes("zap")) lines.push(`- OWASP ZAP dynamic application security testing`);
  lines.push(``);
  lines.push(`### Limitations`);
  lines.push(`- Automated testing cannot replace comprehensive manual penetration testing`);
  lines.push(`- Some vulnerabilities (e.g. business logic flaws) require human expertise to identify`);
  lines.push(`- Tests were performed as an unauthenticated external user unless credentials were provided`);
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
  lines.push(`| **PTES** | Penetration Testing Execution Standard — a methodology for conducting penetration tests. |`);
  lines.push(`| **NIST SP 800-115** | NIST guideline for technical security testing and assessment. |`);
  lines.push(`| **XSS** | Cross-Site Scripting — injection of client-side scripts into pages viewed by other users. |`);
  lines.push(`| **SQLi** | SQL Injection — injection of SQL commands via application input. |`);
  lines.push(`| **CORS** | Cross-Origin Resource Sharing — browser mechanism for cross-origin requests; misconfiguration can allow unauthorized access. |`);
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
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  return `Automated penetration test of ${target.name} (${target.url}) completed with a security score of ${score}/100 (${riskColor(score)}). ${findings.length} finding(s) identified: ${critical} critical, ${high} high, ${findings.filter((f) => f.severity === "medium").length} medium, ${findings.filter((f) => f.severity === "low").length} low. ${critical > 0 || high > 0 ? "Immediate remediation required for critical and high severity issues." : score >= 80 ? "The application demonstrates a strong security posture." : "Security improvements are recommended."}`;
}

export function generateJSONReport(data: ReportData): object {
  const { scan, target, findings, generatedAt } = data;
  const tools = (scan.tools || "").split(",").map((t) => t.trim());
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
    },
    target: {
      name: target.name,
      url: target.url,
      description: target.description,
    },
    summary: {
      securityScore: scan.securityScore,
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
      status: f.status,
      detectedAt: f.createdAt,
    })),
    compliance: {
      frameworks: ["OWASP Top 10:2021", "PTES", "NIST SP 800-115", "CWE Top 25"],
      toolsUsed: tools,
    },
  };
}
