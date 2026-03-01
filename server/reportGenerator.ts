/**
 * Report Generator — produces comprehensive security reports from scan data.
 * Generates Markdown, JSON, and executive summary content.
 */

import { ScanFinding, Scan, Target } from "../drizzle/schema";

interface ReportData {
  scan: Scan;
  target: Target;
  findings: ScanFinding[];
  generatedAt: Date;
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

  // ── Title ──
  lines.push(`# Penetration Test Report`);
  lines.push(``);
  lines.push(`**Generated:** ${generatedAt.toUTCString()}`);
  lines.push(`**Target:** ${target.name} — ${target.url}`);
  lines.push(`**Scan ID:** ${scan.id}`);
  lines.push(`**Triggered By:** ${scan.triggeredBy === "schedule" ? "Scheduled" : "Manual"}`);
  lines.push(`**Duration:** ${scan.startedAt && scan.completedAt ? Math.round((scan.completedAt.getTime() - scan.startedAt.getTime()) / 1000) + "s" : "N/A"}`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Executive Summary ──
  lines.push(`## Executive Summary`);
  lines.push(``);
  lines.push(`This report documents the results of an automated penetration test performed against **${target.name}** (${target.url}). The test was conducted using the PenTest Portal automated security assessment platform, aligned with industry-standard frameworks including OWASP Top 10:2021, PTES (Penetration Testing Execution Standard), NIST SP 800-115, and CWE Top 25.`);
  lines.push(``);
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

  const riskEmoji = score < 40 ? "🔴" : score < 60 ? "🟠" : score < 75 ? "🟡" : score < 90 ? "🔵" : "🟢";
  lines.push(`${riskEmoji} **${riskLabel}** — ${score < 60 ? "Immediate action required to address critical and high severity vulnerabilities." : score < 80 ? "Security improvements recommended to address identified vulnerabilities." : "Good security posture. Continue monitoring and address remaining findings."}`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Test Coverage ──
  lines.push(`## Test Coverage`);
  lines.push(``);
  lines.push(`The following security domains were assessed during this engagement:`);
  lines.push(``);
  const tools = (scan.tools || "").split(",").map((t) => t.trim());
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

  // ── Findings ──
  lines.push(`## Detailed Findings`);
  lines.push(``);

  if (findings.length === 0) {
    lines.push(`✅ **No vulnerabilities detected.** The target passed all security checks for the selected test categories.`);
  } else {
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
        if (f.evidence) {
          lines.push(`**Evidence:**`);
          lines.push(`\`\`\``);
          lines.push(f.evidence.substring(0, 500));
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
  lines.push(`## Recommendations`);
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
  lines.push(`## Standards Compliance`);
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
  lines.push(`## Test Methodology`);
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
  lines.push(`**Report Generated:** ${generatedAt.toUTCString()}`);
  lines.push(`**Generated By:** PenTest Portal Automated Security Assessment Platform`);
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
  return {
    metadata: {
      reportVersion: "1.0",
      generatedAt: generatedAt.toISOString(),
      scanId: scan.id,
      targetId: target.id,
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
      evidence: f.evidence,
      recommendation: f.recommendation,
      cweId: f.cweId,
      owaspCategory: f.owaspCategory,
      status: f.status,
      detectedAt: f.createdAt,
    })),
    compliance: {
      frameworks: ["OWASP Top 10:2021", "PTES", "NIST SP 800-115", "CWE Top 25"],
      toolsUsed: (scan.tools || "").split(",").map((t) => t.trim()),
    },
  };
}
