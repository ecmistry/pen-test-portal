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
});
