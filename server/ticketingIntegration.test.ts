import { describe, it, expect } from "vitest";
import {
  meetsMinSeverity,
  severityToJiraPriority,
  buildJiraDescription,
  buildJiraLabels,
  findingStableId,
} from "./ticketingIntegration";
import type { ScanFinding } from "../drizzle/schema";

const mockFinding: ScanFinding = {
  id: 1,
  scanId: 1,
  category: "SQL Injection",
  severity: "high",
  title: "SQL Injection at /api/users",
  description: "User input is directly concatenated into SQL queries.",
  evidence: "GET /api/users?id=1' OR '1'='1 returned 200 with all user data",
  recommendation: "Use parameterised queries.",
  cweId: "CWE-89",
  owaspCategory: "A03:2021 – Injection",
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  cvssScore: "9.8",
  remediationComplexity: "Medium",
  remediationPriority: "P1",
  businessImpact: {
    financial: "High",
    operational: "High",
    reputational: "High",
    legal: "High",
    rationale: "SQL injection may allow full database compromise.",
  },
  attackTechniques: [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  ],
  iso27001Controls: ["A.14.2.5"],
  poc: {
    curlCommand: "curl 'https://target.com/api/users?id=1%27%20OR%20%271%27=%271'",
    requestRaw: "GET /api/users?id=1' OR '1'='1",
    responseSnippet: "HTTP 200 [{...}]",
    reproductionSteps: ["Send GET request with SQLi payload", "Observe all user data returned"],
  },
  status: "open",
  createdAt: new Date(),
};

describe("meetsMinSeverity", () => {
  it("critical meets any threshold", () => {
    expect(meetsMinSeverity("critical", "critical")).toBe(true);
    expect(meetsMinSeverity("critical", "high")).toBe(true);
    expect(meetsMinSeverity("critical", "medium")).toBe(true);
    expect(meetsMinSeverity("critical", "low")).toBe(true);
  });

  it("high does not meet critical threshold", () => {
    expect(meetsMinSeverity("high", "critical")).toBe(false);
  });

  it("medium meets medium and low thresholds", () => {
    expect(meetsMinSeverity("medium", "medium")).toBe(true);
    expect(meetsMinSeverity("medium", "low")).toBe(true);
    expect(meetsMinSeverity("medium", "high")).toBe(false);
  });

  it("info does not meet any threshold", () => {
    expect(meetsMinSeverity("info", "low")).toBe(false);
  });

  it("low meets low threshold", () => {
    expect(meetsMinSeverity("low", "low")).toBe(true);
  });
});

describe("severityToJiraPriority", () => {
  it("maps critical to Blocker", () => {
    expect(severityToJiraPriority("critical")).toBe("Blocker");
  });

  it("maps high to Critical", () => {
    expect(severityToJiraPriority("high")).toBe("Critical");
  });

  it("maps medium to Major", () => {
    expect(severityToJiraPriority("medium")).toBe("Major");
  });

  it("maps low to Minor", () => {
    expect(severityToJiraPriority("low")).toBe("Minor");
  });

  it("maps unknown to Minor", () => {
    expect(severityToJiraPriority("info")).toBe("Minor");
  });
});

describe("buildJiraDescription", () => {
  it("includes title and severity", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("SQL Injection at /api/users");
    expect(desc).toContain("HIGH");
  });

  it("includes CWE link", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("CWE-89");
    expect(desc).toContain("cwe.mitre.org");
  });

  it("includes CVSS score", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("9.8");
  });

  it("includes business impact table", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("Business Impact");
    expect(desc).toContain("Financial");
  });

  it("includes PoC curl command", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("curl");
  });

  it("includes reproduction steps", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("Send GET request");
  });

  it("includes ATT&CK technique", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("T1190");
  });

  it("includes Ghoststrike attribution", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("Ghoststrike");
  });

  it("handles finding with null fields", () => {
    const minimal: ScanFinding = {
      ...mockFinding,
      description: null,
      cweId: null,
      owaspCategory: null,
      cvssVector: null,
      cvssScore: null,
      businessImpact: null,
      attackTechniques: null,
      poc: null,
    };
    const desc = buildJiraDescription(minimal, "https://target.com");
    expect(desc).toContain("SQL Injection at /api/users");
    expect(desc).not.toContain("h4. Description");
    expect(desc).not.toContain("h4. CVSS Score");
  });
});

describe("buildJiraLabels", () => {
  it("includes ghoststrike and security labels", () => {
    const labels = buildJiraLabels(mockFinding);
    expect(labels).toContain("ghoststrike");
    expect(labels).toContain("security");
  });

  it("includes OWASP category", () => {
    const labels = buildJiraLabels(mockFinding);
    expect(labels).toContain("A03:2021");
  });

  it("includes CWE ID", () => {
    const labels = buildJiraLabels(mockFinding);
    expect(labels).toContain("CWE-89");
  });

  it("includes extra labels", () => {
    const labels = buildJiraLabels(mockFinding, ["sprint-42"]);
    expect(labels).toContain("sprint-42");
  });

  it("deduplicates labels", () => {
    const labels = buildJiraLabels(mockFinding, ["ghoststrike"]);
    const ghoststrikeCount = labels.filter((l) => l === "ghoststrike").length;
    expect(ghoststrikeCount).toBe(1);
  });
});

describe("findingStableId", () => {
  it("returns a string starting with GS-", () => {
    const id = findingStableId(mockFinding, "https://target.com");
    expect(id).toMatch(/^GS-[a-z0-9]+$/);
  });

  it("returns same ID for same finding and target", () => {
    const id1 = findingStableId(mockFinding, "https://target.com");
    const id2 = findingStableId(mockFinding, "https://target.com");
    expect(id1).toBe(id2);
  });

  it("returns different ID for different targets", () => {
    const id1 = findingStableId(mockFinding, "https://target1.com");
    const id2 = findingStableId(mockFinding, "https://target2.com");
    expect(id1).not.toBe(id2);
  });

  it("returns different ID for different finding titles", () => {
    const finding2 = { ...mockFinding, title: "Different title" };
    const id1 = findingStableId(mockFinding, "https://target.com");
    const id2 = findingStableId(finding2, "https://target.com");
    expect(id1).not.toBe(id2);
  });
});
