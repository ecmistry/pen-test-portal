import { describe, expect, it } from "vitest";
import {
  generateMarkdownReport,
  generateExecutiveSummary,
  generateJSONReport,
  securityGrade,
} from "./reportGenerator";
import type { Scan, Target, ScanFinding } from "../drizzle/schema";

const mockScan: Scan = {
  id: 1,
  targetId: 10,
  userId: 1,
  status: "completed",
  tools: "headers,auth,sqli,xss",
  scanMode: "light",
  securityScore: 85,
  riskLevel: "low",
  totalFindings: 2,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 1,
  lowCount: 1,
  infoCount: 0,
  startedAt: new Date("2025-01-01T10:00:00Z"),
  completedAt: new Date("2025-01-01T10:05:00Z"),
  errorMessage: null,
  triggeredBy: "manual",
  scenarios: null,
  trendSummary: null,
  createdAt: new Date(),
};

const mockTarget: Target = {
  id: 10,
  userId: 1,
  name: "Test Site",
  url: "https://example.com",
  description: null,
  tags: null,
  scanFrequency: "manual",
  isActive: true,
  lastScannedAt: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockFindings: ScanFinding[] = [
  {
    id: 1,
    scanId: 1,
    category: "Security Headers",
    severity: "medium",
    title: "Missing CSP",
    description: "Content-Security-Policy not set",
    evidence: null,
    recommendation: "Set CSP header",
    cweId: "CWE-693",
    owaspCategory: "A05:2021 – Security Misconfiguration",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    cvssScore: "5.3",
    remediationComplexity: "Low",
    remediationPriority: "P2",
    businessImpact: { financial: "Low", operational: "Low", reputational: "Low", legal: "Low", rationale: "Missing security headers increase susceptibility to client-side attacks." },
    attackTechniques: [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
    iso27001Controls: ["A.14.1.2"],
    poc: null,
    status: "open",
    createdAt: new Date(),
  },
  {
    id: 2,
    scanId: 1,
    category: "Authentication",
    severity: "high",
    title: "No brute force protection",
    description: "No rate limiting on login endpoint",
    evidence: "10 consecutive failed logins accepted",
    recommendation: "Implement rate limiting",
    cweId: "CWE-307",
    owaspCategory: "A07:2021 – Identification and Authentication Failures",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    cvssScore: "9.1",
    remediationComplexity: "High",
    remediationPriority: "P1",
    businessImpact: { financial: "High", operational: "High", reputational: "Medium", legal: "Medium", rationale: "Weak authentication may allow account takeover." },
    attackTechniques: [{ techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" }],
    iso27001Controls: ["A.9.4.2", "A.9.4.3"],
    poc: null,
    status: "open",
    createdAt: new Date(),
  },
];

const reportData = {
  scan: mockScan,
  target: mockTarget,
  findings: mockFindings,
  generatedAt: new Date("2025-01-01T12:00:00Z"),
};

describe("reportGenerator", () => {
  describe("generateMarkdownReport", () => {
    it("includes target name and URL", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Test Site");
      expect(md).toContain("https://example.com");
    });

    it("includes security score and risk level", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("85/100");
      expect(md).toContain("LOW RISK");
    });

    it("includes findings count by severity", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Total Findings");
      expect(md).toContain("2");
    });
  });

  describe("generateExecutiveSummary", () => {
    it("includes target name, score, and finding counts", () => {
      const summary = generateExecutiveSummary(reportData);
      expect(summary).toContain("Test Site");
      expect(summary).toContain("85/100");
      expect(summary).toContain("2 finding(s)");
    });
  });

  describe("generateMarkdownReport — CVSS", () => {
    it("includes CVSS scores in findings summary table", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("CVSS");
      expect(md).toContain("9.1");
      expect(md).toContain("5.3");
    });

    it("includes CVSS vector in detailed findings", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("CVSSv3.1");
      expect(md).toContain("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
    });
  });

  describe("generateMarkdownReport — Remediation Action Plan", () => {
    it("includes Remediation Action Plan section", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Remediation Action Plan");
    });

    it("includes priority and complexity columns", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Priority");
      expect(md).toContain("Complexity");
      expect(md).toContain("P1");
      expect(md).toContain("P2");
    });

    it("includes timeframe guidance", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("48 hours");
      expect(md).toContain("2 weeks");
    });
  });

  describe("generateMarkdownReport — Business Impact", () => {
    it("includes Business Impact Assessment for findings", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Business Impact Assessment");
      expect(md).toContain("Financial");
      expect(md).toContain("Operational");
      expect(md).toContain("Reputational");
      expect(md).toContain("Legal");
    });
  });

  describe("generateMarkdownReport — MITRE ATT&CK", () => {
    it("includes ATT&CK technique references in detailed findings", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("MITRE ATT&CK");
      expect(md).toContain("T1110");
      expect(md).toContain("T1190");
      expect(md).toContain("attack.mitre.org");
    });

    it("includes ATT&CK coverage summary table", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("ATT&CK Coverage");
      expect(md).toContain("Brute Force");
      expect(md).toContain("Credential Access");
    });
  });

  describe("generateMarkdownReport — ISO 27001", () => {
    it("includes expanded ISO 27001 controls in standards section", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("ISO 27001 Annex A Controls Covered");
      expect(md).toContain("A.9.4.2");
      expect(md).toContain("A.14.1.2");
    });

    it("includes ISO control references in detailed findings", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("ISO 27001");
      expect(md).toContain("A.9.4.2");
      expect(md).toContain("Secure log-on procedures");
    });
  });

  describe("generateMarkdownReport — Standards Compliance", () => {
    it("includes CVSSv3.1 in standards table", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("CVSSv3.1");
      expect(md).toContain("Base score and vector string on every finding");
    });

    it("includes MITRE ATT&CK in standards table", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("MITRE ATT&CK");
      expect(md).toContain("Technique and tactic mapping per finding");
    });

    it("includes CVSS, ATT&CK, ISO 27001 in glossary", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Common Vulnerability Scoring System");
      expect(md).toContain("Adversarial Tactics, Techniques, and Common Knowledge");
      expect(md).toContain("International standard for information security");
    });
  });

  describe("generateJSONReport", () => {
    it("returns object with metadata, target, summary, findings", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      expect(json.metadata).toBeDefined();
      expect(json.target).toBeDefined();
      expect(json.summary).toBeDefined();
      expect(json.findings).toBeDefined();
    });

    it("summary includes securityScore and bySeverity", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const summary = json.summary as Record<string, unknown>;
      expect(summary.securityScore).toBe(85);
      expect(summary.riskLevel).toBe("low");
      const bySeverity = summary.bySeverity as Record<string, number>;
      expect(bySeverity.medium).toBe(1);
      expect(bySeverity.high).toBe(1);
    });

    it("findings include CVSS data", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const authFinding = findings.find((f) => f.category === "Authentication")!;
      const cvss = authFinding.cvss as Record<string, unknown>;
      expect(cvss).not.toBeNull();
      expect(cvss.version).toBe("3.1");
      expect(cvss.baseScore).toBe(9.1);
      expect(cvss.baseSeverity).toBe("CRITICAL");
      expect(cvss.vectorString).toContain("CVSS:3.1/");
    });

    it("findings include business impact", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const sqliLike = findings.find((f) => f.category === "Authentication")!;
      const impact = sqliLike.businessImpact as Record<string, unknown>;
      expect(impact).not.toBeNull();
      expect(impact.financial).toBe("High");
      expect(impact.rationale).toBeTruthy();
    });

    it("findings include remediation with complexity and priority", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const f = findings.find((f) => f.category === "Authentication")!;
      const remediation = f.remediation as Record<string, unknown>;
      expect(remediation.complexity).toBe("High");
      expect(remediation.priority).toBe("P1");
      expect(remediation.timeframe).toBe("48 hours");
    });

    it("findings include ATT&CK techniques", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const f = findings.find((f) => f.category === "Authentication")!;
      const techniques = f.attackTechniques as Array<Record<string, string>>;
      expect(techniques).toHaveLength(1);
      expect(techniques[0].techniqueId).toBe("T1110");
    });

    it("findings include ISO 27001 controls", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const f = findings.find((f) => f.category === "Authentication")!;
      const controls = f.iso27001Controls as string[];
      expect(controls).toContain("A.9.4.2");
    });

    it("compliance frameworks include new standards", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const compliance = json.compliance as Record<string, unknown>;
      const frameworks = compliance.frameworks as string[];
      expect(frameworks).toContain("CVSSv3.1");
      expect(frameworks).toContain("MITRE ATT&CK");
      expect(frameworks).toContain("ISO/IEC 27001");
    });

    it("includes scenarios array in JSON report", () => {
      const scanWithScenarios = { ...mockScan, scenarios: [{ id: "S-003", title: "Data Exfiltration", objective: "Extract data", steps: [{ findingTitle: "SQLi", role: "Initial access" }], likelihood: "High", impact: "High" }] };
      const data = { ...reportData, scan: scanWithScenarios };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const scenarios = json.scenarios as Array<Record<string, unknown>>;
      expect(scenarios).toHaveLength(1);
      expect(scenarios[0].id).toBe("S-003");
    });

    it("includes trend data in JSON report", () => {
      const scanWithTrend = { ...mockScan, trendSummary: { previousScanId: 5, previousScanDate: "2025-06-01", newFindings: 1, resolvedFindings: 2, persistingFindings: 1, newItems: ["New vuln"], resolvedItems: ["Old vuln 1", "Old vuln 2"], persistingItems: ["Persistent"] } };
      const data = { ...reportData, scan: scanWithTrend };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const trend = json.trend as Record<string, unknown>;
      expect(trend).not.toBeNull();
      expect(trend.newFindings).toBe(1);
      expect(trend.resolvedFindings).toBe(2);
    });

    it("includes poc data in JSON findings", () => {
      const findingsWithPoc = [{ ...mockFindings[0], poc: { curlCommand: "curl https://example.com", requestRaw: "GET / HTTP/1.1", responseSnippet: "200 OK", reproductionSteps: ["Step 1"] } }];
      const data = { ...reportData, findings: findingsWithPoc };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const poc = findings[0].poc as Record<string, unknown>;
      expect(poc).not.toBeNull();
      expect(poc.curlCommand).toContain("curl");
    });
  });

  describe("generateMarkdownReport — Phase 2 sections", () => {
    it("renders attack scenarios section when scenarios exist", () => {
      const scanWithScenarios = { ...mockScan, scenarios: [{ id: "S-001", title: "Account Takeover", objective: "Gain access", steps: [{ findingTitle: "Brute force", role: "Credential attack" }], likelihood: "High", impact: "High" }] };
      const data = { ...reportData, scan: scanWithScenarios };
      const md = generateMarkdownReport(data);
      expect(md).toContain("Attack Scenarios");
      expect(md).toContain("S-001");
      expect(md).toContain("Account Takeover");
      expect(md).toContain("Gain access");
      expect(md).toContain("Brute force");
    });

    it("does not render attack scenarios when none exist", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).not.toContain("Attack Scenarios");
    });

    it("renders trend analysis section when trendSummary exists", () => {
      const scanWithTrend = { ...mockScan, trendSummary: { previousScanId: 3, previousScanDate: "2025-05-15", newFindings: 2, resolvedFindings: 1, persistingFindings: 3, newItems: ["New vuln A", "New vuln B"], resolvedItems: ["Old vuln"], persistingItems: ["P1", "P2", "P3"] } };
      const data = { ...reportData, scan: scanWithTrend };
      const md = generateMarkdownReport(data);
      expect(md).toContain("Trend Analysis");
      expect(md).toContain("previous scan #3");
      expect(md).toContain("New vuln A");
      expect(md).toContain("Old vuln");
    });

    it("does not render trend section when no trendSummary", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).not.toContain("Trend Analysis");
    });

    it("renders PoC section when finding has poc data", () => {
      const findingsWithPoc = [{ ...mockFindings[0], poc: { curlCommand: "curl https://example.com/vuln", requestRaw: "GET /vuln HTTP/1.1\r\nHost: example.com", responseSnippet: "<html>error</html>", reproductionSteps: ["1. Send request", "2. Observe response"] } }];
      const data = { ...reportData, findings: findingsWithPoc };
      const md = generateMarkdownReport(data);
      expect(md).toContain("Proof of Concept");
      expect(md).toContain("curl https://example.com/vuln");
      expect(md).toContain("GET /vuln HTTP/1.1");
      expect(md).toContain("1. Send request");
    });

    it("does not render PoC section when finding has no poc", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).not.toContain("Proof of Concept");
    });

    it("includes TLS tool description in test coverage", () => {
      const scanWithTls = { ...mockScan, tools: "headers,auth,tls" };
      const data = { ...reportData, scan: scanWithTls };
      const md = generateMarkdownReport(data);
      expect(md).toContain("TLS");
      expect(md).toContain("SSL/TLS Analysis");
    });

    it("adjusts section numbers when scenarios and trend present", () => {
      const scanFull = {
        ...mockScan,
        scenarios: [{ id: "S-001", title: "Test", objective: "Test", steps: [{ findingTitle: "F", role: "R" }], likelihood: "High", impact: "High" }],
        trendSummary: { previousScanId: 1, previousScanDate: "2025-01-01", newFindings: 0, resolvedFindings: 0, persistingFindings: 0, newItems: [], resolvedItems: [], persistingItems: [] },
      };
      const data = { ...reportData, scan: scanFull };
      const md = generateMarkdownReport(data);
      expect(md).toContain("## 7. Attack Scenarios");
      expect(md).toContain("## 8. Trend Analysis");
      expect(md).toContain("## 9. Standards Compliance");
    });
  });

  describe("Phase 3 — Executive Summary & Security Grade", () => {
    it("securityGrade returns A for score >= 90", () => {
      expect(securityGrade(95)).toEqual({ grade: "A", label: "Excellent" });
      expect(securityGrade(90)).toEqual({ grade: "A", label: "Excellent" });
    });

    it("securityGrade returns B for score 80-89", () => {
      expect(securityGrade(85)).toEqual({ grade: "B", label: "Good" });
      expect(securityGrade(80)).toEqual({ grade: "B", label: "Good" });
    });

    it("securityGrade returns C for score 70-79", () => {
      expect(securityGrade(75)).toEqual({ grade: "C", label: "Adequate" });
    });

    it("securityGrade returns D for score 55-69", () => {
      expect(securityGrade(60)).toEqual({ grade: "D", label: "Below Average" });
    });

    it("securityGrade returns F for score < 55", () => {
      expect(securityGrade(30)).toEqual({ grade: "F", label: "Critical" });
      expect(securityGrade(0)).toEqual({ grade: "F", label: "Critical" });
    });

    it("Markdown report includes Security Grade", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Security Grade");
      expect(md).toContain("Grade B");
    });

    it("Markdown report includes non-technical summary header", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("For decision-makers");
    });

    it("Markdown report includes Recommended Immediate Actions for P1 findings", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Recommended Immediate Actions");
      expect(md).toContain("Implement rate limiting");
    });

    it("Markdown report includes What Is Working Well section", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("What Is Working Well");
    });

    it("Markdown report includes Top Risks for critical/high findings", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Top Risks");
      expect(md).toContain("No brute force protection");
    });

    it("generateExecutiveSummary includes grade", () => {
      const summary = generateExecutiveSummary(reportData);
      expect(summary).toContain("grade of B");
      expect(summary).toContain("Good");
    });

    it("generateExecutiveSummary includes top risks when critical/high findings exist", () => {
      const summary = generateExecutiveSummary(reportData);
      expect(summary).toContain("Top risks");
      expect(summary).toContain("No brute force protection");
    });

    it("JSON report includes securityGrade", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const summary = json.summary as Record<string, unknown>;
      const grade = summary.securityGrade as Record<string, string>;
      expect(grade.grade).toBe("B");
      expect(grade.label).toBe("Good");
    });

    it("includes business logic tool description in test coverage", () => {
      const scanWithLogic = { ...mockScan, tools: "headers,logic" };
      const data = { ...reportData, scan: scanWithLogic };
      const md = generateMarkdownReport(data);
      expect(md).toContain("Business Logic Tests");
    });

    it("includes graphql tool description in test coverage", () => {
      const scanWithGql = { ...mockScan, tools: "headers,graphql" };
      const data = { ...reportData, scan: scanWithGql };
      const md = generateMarkdownReport(data);
      expect(md).toContain("GraphQL Security");
    });
  });

  describe("generateMarkdownReport — edge cases", () => {
    it("shows 'No vulnerabilities detected' for empty findings", () => {
      const data = { ...reportData, findings: [] };
      const md = generateMarkdownReport(data);
      expect(md).toContain("No vulnerabilities detected");
      expect(md).not.toContain("Detailed Findings");
    });

    it("truncates finding titles longer than 55 chars in summary table", () => {
      const longTitle = "A".repeat(60);
      const longFinding = { ...mockFindings[0], title: longTitle };
      const data = { ...reportData, findings: [longFinding] };
      const md = generateMarkdownReport(data);
      const summarySection = md.split("## 4. Findings Summary")[1]?.split("## 5.")[0] ?? "";
      expect(summarySection).toContain("A".repeat(52) + "...");
      expect(summarySection).not.toContain("A".repeat(56));
    });

    it("shows 'N/A' for duration when startedAt is null", () => {
      const scanNoStart = { ...mockScan, startedAt: null };
      const data = { ...reportData, scan: scanNoStart };
      const md = generateMarkdownReport(data);
      expect(md).toContain("N/A");
    });

    it("shows 'N/A' for duration when completedAt is null", () => {
      const scanNoEnd = { ...mockScan, completedAt: null };
      const data = { ...reportData, scan: scanNoEnd };
      const md = generateMarkdownReport(data);
      expect(md).toContain("N/A");
    });

    it("shows 'Scheduled' when triggeredBy is schedule", () => {
      const scheduledScan = { ...mockScan, triggeredBy: "schedule" as const };
      const data = { ...reportData, scan: scheduledScan };
      const md = generateMarkdownReport(data);
      expect(md).toContain("Scheduled");
    });

    it("shows 'Manual' when triggeredBy is manual", () => {
      const md = generateMarkdownReport(reportData);
      expect(md).toContain("Manual");
    });

    it("shows OPEN as default status when finding status is null", () => {
      const nullStatusFinding = { ...mockFindings[0], status: null };
      const data = { ...reportData, findings: [nullStatusFinding] };
      const md = generateMarkdownReport(data);
      expect(md).toContain("OPEN");
    });

    it("truncates evidence longer than 3000 chars", () => {
      const longEvidence = "X".repeat(3500);
      const findingWithEvidence = { ...mockFindings[0], evidence: longEvidence };
      const data = { ...reportData, findings: [findingWithEvidence] };
      const md = generateMarkdownReport(data);
      expect(md).toContain("[... truncated for length ...]");
    });

    it("includes correct risk emoji for each risk level", () => {
      const criticalScan = { ...mockScan, securityScore: 30 };
      const md = generateMarkdownReport({ ...reportData, scan: criticalScan });
      expect(md).toContain("CRITICAL RISK");

      const highScan = { ...mockScan, securityScore: 50 };
      const mdHigh = generateMarkdownReport({ ...reportData, scan: highScan });
      expect(mdHigh).toContain("HIGH RISK");

      const medScan = { ...mockScan, securityScore: 70 };
      const mdMed = generateMarkdownReport({ ...reportData, scan: medScan });
      expect(mdMed).toContain("MEDIUM RISK");

      const minScan = { ...mockScan, securityScore: 95 };
      const mdMin = generateMarkdownReport({ ...reportData, scan: minScan });
      expect(mdMin).toContain("MINIMAL RISK");
    });

    it("shows scan mode, defaulting to light when null", () => {
      const scanNull = { ...mockScan, scanMode: null };
      const data = { ...reportData, scan: scanNull };
      const md = generateMarkdownReport(data);
      expect(md).toContain("light");
    });

    it("uses tool name as description for unknown tools", () => {
      const scanUnknownTool = { ...mockScan, tools: "headers,customtool" };
      const data = { ...reportData, scan: scanUnknownTool };
      const md = generateMarkdownReport(data);
      expect(md).toContain("customtool");
    });
  });

  describe("generateExecutiveSummary — edge cases", () => {
    it("includes 'strong security posture' when score >= 80 and no critical/high", () => {
      const safeScan = { ...mockScan, securityScore: 90 };
      const safeFindings = [{ ...mockFindings[0], severity: "low" as const }];
      const data = { scan: safeScan, target: mockTarget, findings: safeFindings, generatedAt: new Date() };
      const summary = generateExecutiveSummary(data);
      expect(summary).toContain("strong security posture");
    });

    it("includes 'Security improvements are recommended' when score < 80 and no critical/high", () => {
      const okScan = { ...mockScan, securityScore: 65 };
      const okFindings = [{ ...mockFindings[0], severity: "medium" as const }];
      const data = { scan: okScan, target: mockTarget, findings: okFindings, generatedAt: new Date() };
      const summary = generateExecutiveSummary(data);
      expect(summary).toContain("Security improvements are recommended");
    });

    it("handles zero findings", () => {
      const cleanScan = { ...mockScan, securityScore: 100, totalFindings: 0 };
      const data = { scan: cleanScan, target: mockTarget, findings: [], generatedAt: new Date() };
      const summary = generateExecutiveSummary(data);
      expect(summary).toContain("0 finding(s)");
      expect(summary).toContain("strong security posture");
    });

    it("limits top risks to 3", () => {
      const findings = Array(5).fill(null).map((_, i) => ({
        ...mockFindings[1],
        id: i + 10,
        title: `Critical Issue ${i + 1}`,
        severity: "critical" as const,
      }));
      const data = { scan: { ...mockScan, securityScore: 20 }, target: mockTarget, findings, generatedAt: new Date() };
      const summary = generateExecutiveSummary(data);
      expect(summary).toContain("Critical Issue 1");
      expect(summary).toContain("Critical Issue 3");
      expect(summary).not.toContain("Critical Issue 4");
    });
  });

  describe("generateJSONReport — edge cases", () => {
    it("returns null cvss when finding has no cvssScore", () => {
      const findingNoCvss = { ...mockFindings[0], cvssScore: null, cvssVector: null };
      const data = { ...reportData, findings: [findingNoCvss] };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      expect(findings[0].cvss).toBeNull();
    });

    it("returns baseSeverity LOW for CVSS score between 0.1 and 3.9", () => {
      const lowCvss = { ...mockFindings[0], cvssScore: "3.1", cvssVector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N" };
      const data = { ...reportData, findings: [lowCvss] };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const cvss = findings[0].cvss as Record<string, unknown>;
      expect(cvss.baseSeverity).toBe("LOW");
    });

    it("returns baseSeverity MEDIUM for CVSS score 5.3", () => {
      const data = { ...reportData, findings: [mockFindings[0]] };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const cvss = findings[0].cvss as Record<string, unknown>;
      expect(cvss.baseSeverity).toBe("MEDIUM");
    });

    it("returns baseSeverity HIGH for CVSS score 7.5", () => {
      const highCvss = { ...mockFindings[0], cvssScore: "7.5" };
      const data = { ...reportData, findings: [highCvss] };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const cvss = findings[0].cvss as Record<string, unknown>;
      expect(cvss.baseSeverity).toBe("HIGH");
    });

    it("returns baseSeverity CRITICAL for CVSS score 9.8", () => {
      const critCvss = { ...mockFindings[0], cvssScore: "9.8" };
      const data = { ...reportData, findings: [critCvss] };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const cvss = findings[0].cvss as Record<string, unknown>;
      expect(cvss.baseSeverity).toBe("CRITICAL");
    });

    it("returns correct timeframe for each priority", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      const findings = json.findings as Array<Record<string, unknown>>;
      const p1Finding = findings.find((f) => (f.remediation as any).priority === "P1");
      const p2Finding = findings.find((f) => (f.remediation as any).priority === "P2");
      expect((p1Finding?.remediation as any).timeframe).toBe("48 hours");
      expect((p2Finding?.remediation as any).timeframe).toBe("2 weeks");
    });

    it("returns empty scenarios array when no scenarios", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      expect(json.scenarios).toEqual([]);
    });

    it("returns null trend when no trendSummary", () => {
      const json = generateJSONReport(reportData) as Record<string, unknown>;
      expect(json.trend).toBeNull();
    });

    it("returns scan mode defaulting to light when null", () => {
      const scanNull = { ...mockScan, scanMode: null };
      const data = { ...reportData, scan: scanNull };
      const json = generateJSONReport(data) as Record<string, unknown>;
      const scope = json.scope as Record<string, unknown>;
      expect(scope.scanMode).toBe("light");
    });
  });

  describe("securityGrade — boundary cases", () => {
    it("securityGrade(55) returns D", () => {
      expect(securityGrade(55)).toEqual({ grade: "D", label: "Below Average" });
    });

    it("securityGrade(54) returns F", () => {
      expect(securityGrade(54)).toEqual({ grade: "F", label: "Critical" });
    });

    it("securityGrade(70) returns C", () => {
      expect(securityGrade(70)).toEqual({ grade: "C", label: "Adequate" });
    });

    it("securityGrade(69) returns D", () => {
      expect(securityGrade(69)).toEqual({ grade: "D", label: "Below Average" });
    });

    it("securityGrade(79) returns C", () => {
      expect(securityGrade(79)).toEqual({ grade: "C", label: "Adequate" });
    });

    it("securityGrade(89) returns B", () => {
      expect(securityGrade(89)).toEqual({ grade: "B", label: "Good" });
    });

    it("securityGrade(100) returns A", () => {
      expect(securityGrade(100)).toEqual({ grade: "A", label: "Excellent" });
    });
  });

  describe("OWASP API Security Top 10:2023 coverage", () => {
    it("includes API Security framework in JSON compliance.frameworks", () => {
      const json = generateJSONReport({ scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt: new Date() }) as any;
      expect(json.compliance.frameworks).toContain("OWASP API Security Top 10:2023");
    });

    it("includes apiSecurityCategory on JSON findings", () => {
      const json = generateJSONReport({ scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt: new Date() }) as any;
      const authFinding = json.findings.find((f: any) => f.category === "Authentication");
      expect(authFinding.apiSecurityCategory).toEqual({ id: "API2:2023", name: "Broken Authentication" });
    });

    it("includes apiSecurityCategory null for unmapped categories", () => {
      const finding: ScanFinding = {
        id: 99, scanId: 1, category: "Connectivity", severity: "info",
        title: "Connection test", description: null, evidence: null,
        recommendation: null, cweId: null, owaspCategory: null,
        cvssVector: null, cvssScore: null, remediationComplexity: null,
        remediationPriority: null, businessImpact: null,
        attackTechniques: null, iso27001Controls: null,
        poc: null, status: "info", createdAt: new Date(),
      };
      const json = generateJSONReport({ scan: mockScan, target: mockTarget, findings: [finding], generatedAt: new Date() }) as any;
      expect(json.findings[0].apiSecurityCategory).toBeNull();
    });

    it("renders API Security Top 10 in Markdown compliance table", () => {
      const md = generateMarkdownReport({ scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt: new Date() });
      expect(md).toContain("OWASP API Security Top 10:2023");
    });

    it("renders API Security coverage section when findings map to API categories", () => {
      const md = generateMarkdownReport({ scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt: new Date() });
      expect(md).toContain("### OWASP API Security Top 10:2023 Coverage");
      expect(md).toContain("API2:2023");
      expect(md).toContain("API8:2023");
    });

    it("shows OWASP API category in finding detail table", () => {
      const md = generateMarkdownReport({ scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt: new Date() });
      expect(md).toContain("OWASP API");
      expect(md).toContain("Broken Authentication");
    });

    it("includes OWASP API Top 10 in glossary", () => {
      const md = generateMarkdownReport({ scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt: new Date() });
      expect(md).toContain("OWASP API Top 10");
    });

    it("maps Authorization findings to API1:2023 in JSON", () => {
      const authFinding: ScanFinding = {
        id: 99, scanId: 1, category: "Authorization", severity: "high",
        title: "Vertical Privilege Escalation", description: "Admin endpoint accessible as user",
        evidence: "[Auth Context] Discovered As: standard_user | Required Level: admin\nAdmin: 200 User: 200",
        recommendation: "Add role checks", cweId: "CWE-269",
        owaspCategory: "A01:2021 – Broken Access Control",
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", cvssScore: "8.1",
        remediationComplexity: "High", remediationPriority: "P1",
        businessImpact: null, attackTechniques: null, iso27001Controls: null,
        poc: null, status: "open", createdAt: new Date(),
      };
      const json = generateJSONReport({ scan: mockScan, target: mockTarget, findings: [authFinding], generatedAt: new Date() }) as any;
      expect(json.findings[0].apiSecurityCategory).toEqual({ id: "API1:2023", name: "Broken Object Level Authorization" });
      expect(json.findings[0].authContext).toBeDefined();
      expect(json.findings[0].authContext.discoveredAs).toBe("standard_user");
      expect(json.findings[0].authContext.requiredLevel).toBe("admin");
    });
  });

  describe("Auth context in reports", () => {
    it("renders auth context metadata in Markdown finding detail", () => {
      const authFinding: ScanFinding = {
        id: 99, scanId: 1, category: "Authorization", severity: "high",
        title: "Vertical Privilege Escalation", description: null,
        evidence: "[Auth Context] Discovered As: standard_user | Exploitable As: standard_user | Required Level: admin | Endpoint: GET /api/admin\nAdmin: 200",
        recommendation: null, cweId: "CWE-269",
        owaspCategory: "A01:2021", cvssVector: null, cvssScore: null,
        remediationComplexity: null, remediationPriority: null,
        businessImpact: null, attackTechniques: null, iso27001Controls: null,
        poc: null, status: "open", createdAt: new Date(),
      };
      const md = generateMarkdownReport({ scan: mockScan, target: mockTarget, findings: [authFinding], generatedAt: new Date() });
      expect(md).toContain("Discovered As");
      expect(md).toContain("standard_user");
      expect(md).toContain("Required Level");
      expect(md).toContain("admin");
      expect(md).toContain("Endpoint");
    });

    it("returns null authContext in JSON for findings without auth metadata", () => {
      const json = generateJSONReport({ scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt: new Date() }) as any;
      expect(json.findings[0].authContext).toBeNull();
    });

    it("includes auth-roles in tool descriptions", () => {
      const scanWithAuthRoles = { ...mockScan, tools: "headers,auth-roles" };
      const md = generateMarkdownReport({ scan: scanWithAuthRoles, target: mockTarget, findings: [], generatedAt: new Date() });
      expect(md).toContain("AUTH-ROLES");
      expect(md).toContain("Authenticated Multi-Role Scanning");
    });

    it("includes sca in tool descriptions", () => {
      const scanWithSca = { ...mockScan, tools: "headers,sca" };
      const md = generateMarkdownReport({ scan: scanWithSca, target: mockTarget, findings: [], generatedAt: new Date() });
      expect(md).toContain("SCA");
      expect(md).toContain("Dependency / SCA Scanning");
    });

    it("includes A06 in OWASP coverage line", () => {
      const md = generateMarkdownReport({ scan: mockScan, target: mockTarget, findings: [], generatedAt: new Date() });
      expect(md).toContain("A06");
    });
  });
});
