import { describe, expect, it } from "vitest";
import {
  generateMarkdownReport,
  generateExecutiveSummary,
  generateJSONReport,
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
    category: "Headers",
    severity: "medium",
    title: "Missing CSP",
    description: "Content-Security-Policy not set",
    evidence: null,
    recommendation: "Set CSP header",
    cweId: null,
    owaspCategory: null,
    status: "open",
    createdAt: new Date(),
  },
  {
    id: 2,
    scanId: 1,
    category: "Auth",
    severity: "low",
    title: "Session timeout",
    description: "Long session timeout",
    evidence: null,
    recommendation: "Reduce timeout",
    cweId: null,
    owaspCategory: null,
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
      expect(bySeverity.low).toBe(1);
    });
  });
});
