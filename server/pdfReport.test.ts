import { describe, expect, it } from "vitest";
import { generatePdfReport } from "./pdfReport";
import type { ReportData } from "./reportGenerator";
import type { Scan, Target, ScanFinding } from "../drizzle/schema";

const mockScan: Scan = {
  id: 1,
  targetId: 10,
  userId: 1,
  status: "completed",
  tools: "headers,auth,sqli,xss",
  scanMode: "light",
  authMode: null,
  authMeta: null,
  securityScore: 85,
  riskLevel: "low",
  totalFindings: 1,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 1,
  lowCount: 0,
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
  repoUrl: null,
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
    businessImpact: { financial: "Low", operational: "Low", reputational: "Low", legal: "Low", rationale: "Test rationale" },
    attackTechniques: [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
    iso27001Controls: ["A.14.1.2"],
    poc: null,
    affectedUrl: "https://example.com",
    affectedComponent: "HTTP Response Headers",
    sourceFile: null,
    sourceLine: null,
    sourceSnippet: null,
    authContext: null,
    status: "open",
    createdAt: new Date(),
  },
];

const reportData: ReportData = {
  scan: mockScan,
  target: mockTarget,
  findings: mockFindings,
  generatedAt: new Date("2025-01-01T12:00:00Z"),
};

describe("pdfReport", () => {
  it("returns a Buffer", () => {
    const buf = generatePdfReport(reportData);
    expect(Buffer.isBuffer(buf)).toBe(true);
  });

  it("output is a valid PDF (starts with %PDF)", () => {
    const buf = generatePdfReport(reportData);
    expect(buf.length).toBeGreaterThan(100);
    expect(buf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
  });

  it("includes target name in PDF content", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("Test Site");
    expect(str).toContain("https://example.com");
  });

  it("handles empty findings", () => {
    const data: ReportData = { ...reportData, findings: [] };
    const buf = generatePdfReport(data);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
  });

  it("includes CVSS score in PDF content", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("5.3");
    expect(str).toContain("P2");
  });

  it("includes ATT&CK technique ID in PDF content", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("T1190");
  });

  it("includes business impact ratings in PDF content", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("Business Impact");
  });

  it("includes CVSSv3.1 and ATT&CK in standards section", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("CVSSv3.1");
    expect(str).toContain("ATT&CK");
  });

  it("renders attack scenarios section in PDF when scenarios exist", () => {
    const scanWithScenarios = { ...mockScan, scenarios: [{ id: "S-003", title: "Data Exfiltration", objective: "Extract data", steps: [{ findingTitle: "SQLi", role: "Initial" }], likelihood: "High", impact: "High" }] };
    const data = { ...reportData, scan: scanWithScenarios };
    const buf = generatePdfReport(data);
    const str = buf.toString("latin1");
    expect(str).toContain("Attack Scenarios");
    expect(str).toContain("Data Exfiltration");
  });

  it("renders trend analysis section in PDF when trendSummary exists", () => {
    const scanWithTrend = { ...mockScan, trendSummary: { previousScanId: 2, previousScanDate: "2025-06-01", newFindings: 1, resolvedFindings: 2, persistingFindings: 3, newItems: ["New"], resolvedItems: ["Resolved1", "Resolved2"], persistingItems: ["P1", "P2", "P3"] } };
    const data = { ...reportData, scan: scanWithTrend };
    const buf = generatePdfReport(data);
    const str = buf.toString("latin1");
    expect(str).toContain("Trend Analysis");
    expect(str).toContain("1 new");
  });

  it("does not render scenarios/trend sections when absent", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).not.toContain("Attack Scenarios");
    expect(str).not.toContain("Trend Analysis");
  });

  it("shows CRITICAL RISK for score < 40", () => {
    const critScan = { ...mockScan, securityScore: 30 };
    const buf = generatePdfReport({ ...reportData, scan: critScan });
    const str = buf.toString("latin1");
    expect(str).toContain("CRITICAL RISK");
  });

  it("shows HIGH RISK for score 40-59", () => {
    const highScan = { ...mockScan, securityScore: 50 };
    const buf = generatePdfReport({ ...reportData, scan: highScan });
    const str = buf.toString("latin1");
    expect(str).toContain("HIGH RISK");
  });

  it("shows MEDIUM RISK for score 60-74", () => {
    const medScan = { ...mockScan, securityScore: 65 };
    const buf = generatePdfReport({ ...reportData, scan: medScan });
    const str = buf.toString("latin1");
    expect(str).toContain("MEDIUM RISK");
  });

  it("shows MINIMAL RISK for score >= 90", () => {
    const minScan = { ...mockScan, securityScore: 95 };
    const buf = generatePdfReport({ ...reportData, scan: minScan });
    const str = buf.toString("latin1");
    expect(str).toContain("MINIMAL RISK");
  });

  it("shows 'Scheduled' when triggeredBy is schedule", () => {
    const scheduledScan = { ...mockScan, triggeredBy: "schedule" as const };
    const buf = generatePdfReport({ ...reportData, scan: scheduledScan });
    const str = buf.toString("latin1");
    expect(str).toContain("Scheduled");
  });

  it("shows scan mode defaulting to light when null", () => {
    const nullModeScan = { ...mockScan, scanMode: null };
    const buf = generatePdfReport({ ...reportData, scan: nullModeScan });
    const str = buf.toString("latin1");
    expect(str).toContain("light");
  });

  it("does not crash with null description and null recommendation", () => {
    const nullFinding = { ...mockFindings[0], description: null, recommendation: null };
    const data: ReportData = { ...reportData, findings: [nullFinding] };
    const buf = generatePdfReport(data);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
  });

  it("handles null status defaulting to OPEN", () => {
    const nullStatusFinding = { ...mockFindings[0], status: null };
    const data: ReportData = { ...reportData, findings: [nullStatusFinding] };
    const buf = generatePdfReport(data);
    const str = buf.toString("latin1");
    expect(str).toContain("OPEN");
  });

  it("handles > 30 findings with truncation message", () => {
    const manyFindings = Array(35).fill(null).map((_, i) => ({
      ...mockFindings[0],
      id: i + 1,
      title: `Finding ${i + 1}`,
    }));
    const data: ReportData = { ...reportData, findings: manyFindings };
    const buf = generatePdfReport(data);
    const str = buf.toString("latin1");
    expect(str).toContain("5 more finding");
  });

  it("renders PoC data when finding has poc", () => {
    const findingWithPoc = {
      ...mockFindings[0],
      poc: { curlCommand: "curl https://example.com", requestRaw: "GET / HTTP/1.1", responseSnippet: "200 OK", reproductionSteps: ["Step 1"] },
    };
    const data: ReportData = { ...reportData, findings: [findingWithPoc] };
    const buf = generatePdfReport(data);
    expect(Buffer.isBuffer(buf)).toBe(true);
  });

  it("includes security grade information", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("85/100");
  });

  it("shows UNAUTHENTICATED SCAN banner for unauthenticated scan", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("UNAUTHENTICATED SCAN");
  });

  it("shows AUTHENTICATED SCAN banner for authenticated scan", () => {
    const authScan: Scan = { ...mockScan, authMode: "authenticated", authMeta: { authMode: "authenticated", authMethod: "session-cookie", authRole: "admin" } };
    const data: ReportData = { ...reportData, scan: authScan };
    const buf = generatePdfReport(data);
    const str = buf.toString("latin1");
    expect(str).toContain("AUTHENTICATED SCAN");
  });

  it("shows auth mode in scan metadata line", () => {
    const buf = generatePdfReport(reportData);
    const str = buf.toString("latin1");
    expect(str).toContain("Unauthenticated");
  });

  it("shows Authenticated in scope for auth scan", () => {
    const authScan: Scan = { ...mockScan, authMode: "authenticated", authMeta: { authMode: "authenticated" } };
    const data: ReportData = { ...reportData, scan: authScan };
    const buf = generatePdfReport(data);
    const str = buf.toString("latin1");
    expect(str).toContain("Authenticated");
    expect(str).toContain("Full application surface");
  });

  it("includes pre/post auth counts for authenticated scan", () => {
    const authScan: Scan = { ...mockScan, authMode: "authenticated", authMeta: { authMode: "authenticated" } };
    const authFindings: ScanFinding[] = [{ ...mockFindings[0], authContext: "pre-auth" }];
    const data: ReportData = { ...reportData, scan: authScan, findings: authFindings };
    const buf = generatePdfReport(data);
    const str = buf.toString("latin1");
    expect(str).toContain("Pre-auth");
  });
});
