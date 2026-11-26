import { describe, expect, it } from "vitest";
import { generateSarifReport } from "./sarif";
import type { ReportData } from "./reportGenerator";

describe("generateSarifReport", () => {
  it("emits SARIF 2.1 with results", () => {
    const data = {
      generatedAt: new Date("2026-01-01T00:00:00Z"),
      scan: {
        id: 1,
        status: "completed",
        securityScore: 70,
        riskLevel: "medium",
        completedAt: new Date("2026-01-01T00:00:00Z"),
        tools: "headers",
      },
      target: { id: 9, name: "App", url: "https://app.example.com" },
      findings: [
        {
          id: 1,
          title: "Missing CSP",
          category: "Security Headers",
          severity: "medium",
          description: "CSP missing",
          status: "open",
          cweId: "CWE-693",
          owaspCategory: null,
          evidence: null,
        },
        {
          id: 2,
          title: "Waived thing",
          category: "XSS",
          severity: "high",
          description: "x",
          status: "false_positive",
          cweId: null,
        },
      ],
    } as unknown as ReportData;

    const sarif = generateSarifReport(data) as any;
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe("CWE-693");
    expect(sarif.runs[0].tool.driver.name).toBe("Ghoststrike");
  });
});
