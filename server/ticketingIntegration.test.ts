import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  meetsMinSeverity,
  severityToJiraPriority,
  buildJiraDescription,
  buildJiraLabels,
  findingStableId,
  pushFindingToJira,
  pushFindingToGitHub,
  pushFindingToLinear,
  pushFindingsToTicketing,
} from "./ticketingIntegration";
import type { ScanFinding } from "../drizzle/schema";
import type { JiraConfig, GitHubConfig, LinearConfig } from "./ticketingIntegration";

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
  authContext: null,
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

// ─── buildJiraDescription edge cases ─────────────────────────────────────────

describe("buildJiraDescription — edge cases", () => {
  it("includes OWASP category when present", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("A03:2021");
  });

  it("includes recommendation section", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("parameterised queries");
  });

  it("includes the target URL", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain("https://target.com");
  });

  it("includes date of generation", () => {
    const desc = buildJiraDescription(mockFinding, "https://target.com");
    expect(desc).toContain(new Date().toISOString().split("T")[0]);
  });
});

// ─── buildJiraLabels edge cases ──────────────────────────────────────────────

describe("buildJiraLabels — edge cases", () => {
  it("handles finding without CWE or OWASP", () => {
    const minimal: ScanFinding = { ...mockFinding, cweId: null, owaspCategory: null };
    const labels = buildJiraLabels(minimal);
    expect(labels).toContain("ghoststrike");
    expect(labels).toContain("security");
    expect(labels).not.toContain("CWE-89");
  });

  it("handles empty extra labels array", () => {
    const labels = buildJiraLabels(mockFinding, []);
    expect(labels).toContain("ghoststrike");
    expect(labels.length).toBeGreaterThanOrEqual(3);
  });
});

// ─── pushFindingToJira ───────────────────────────────────────────────────────

describe("pushFindingToJira", () => {
  const jiraConfig: JiraConfig = {
    enabled: true,
    baseUrl: "https://test.atlassian.net",
    projectKey: "SEC",
    apiToken: "test-token",
    email: "test@test.com",
    minSeverity: "medium",
    deduplication: false,
  };

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("skips findings below severity threshold", async () => {
    const lowFinding: ScanFinding = { ...mockFinding, severity: "info" };
    const result = await pushFindingToJira(jiraConfig, lowFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.reason).toContain("Below");
  });

  it("returns created in dry-run mode", async () => {
    const result = await pushFindingToJira(jiraConfig, mockFinding, "https://target.com", true);
    expect(result.action).toBe("created");
    expect(result.reason).toBe("dry-run");
    expect(result.provider).toBe("jira");
  });

  it("creates a ticket on success", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      status: 201,
      headers: new Map([["content-type", "application/json"]]),
      json: () => Promise.resolve({ key: "SEC-42" }),
    });
    const result = await pushFindingToJira(jiraConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("created");
    expect(result.ticketKey).toBe("SEC-42");
    expect(result.ticketUrl).toContain("SEC-42");
  });

  it("handles API error gracefully", async () => {
    (globalThis.fetch as any).mockRejectedValue(new Error("Network failure"));
    const result = await pushFindingToJira(jiraConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.reason).toContain("Network failure");
  });

  it("handles non-201 status", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      status: 400,
      headers: new Map([["content-type", "application/json"]]),
      json: () => Promise.resolve({ errors: ["Invalid project"] }),
    });
    const result = await pushFindingToJira(jiraConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.reason).toContain("400");
  });
});

// ─── pushFindingToGitHub ─────────────────────────────────────────────────────

describe("pushFindingToGitHub", () => {
  const ghConfig: GitHubConfig = {
    enabled: true,
    repo: "org/repo",
    token: "ghp_test",
    minSeverity: "medium",
  };

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("skips findings below severity threshold", async () => {
    const lowFinding: ScanFinding = { ...mockFinding, severity: "low" };
    const result = await pushFindingToGitHub(ghConfig, lowFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.provider).toBe("github");
  });

  it("returns created in dry-run mode", async () => {
    const result = await pushFindingToGitHub(ghConfig, mockFinding, "https://target.com", true);
    expect(result.action).toBe("created");
    expect(result.reason).toBe("dry-run");
  });

  it("creates a GitHub issue on success", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ number: 7, html_url: "https://github.com/org/repo/issues/7" }),
    });
    const result = await pushFindingToGitHub(ghConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("created");
    expect(result.ticketKey).toBe("#7");
    expect(result.ticketUrl).toContain("issues/7");
  });

  it("handles API error gracefully", async () => {
    (globalThis.fetch as any).mockRejectedValue(new Error("rate limited"));
    const result = await pushFindingToGitHub(ghConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.reason).toContain("rate limited");
  });

  it("handles non-ok response", async () => {
    (globalThis.fetch as any).mockResolvedValue({ ok: false, status: 422 });
    const result = await pushFindingToGitHub(ghConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.reason).toContain("422");
  });
});

// ─── pushFindingToLinear ─────────────────────────────────────────────────────

describe("pushFindingToLinear", () => {
  const linearConfig: LinearConfig = {
    enabled: true,
    apiKey: "lin_api_test",
    teamId: "team-1",
    minSeverity: "high",
  };

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("skips findings below severity threshold", async () => {
    const medFinding: ScanFinding = { ...mockFinding, severity: "medium" };
    const result = await pushFindingToLinear(linearConfig, medFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.provider).toBe("linear");
  });

  it("returns created in dry-run mode", async () => {
    const result = await pushFindingToLinear(linearConfig, mockFinding, "https://target.com", true);
    expect(result.action).toBe("created");
    expect(result.reason).toBe("dry-run");
  });

  it("creates a Linear issue on success", async () => {
    (globalThis.fetch as any).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        data: { issueCreate: { success: true, issue: { id: "id1", identifier: "SEC-1", url: "https://linear.app/issue/SEC-1" } } },
      }),
    });
    const result = await pushFindingToLinear(linearConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("created");
    expect(result.ticketKey).toBe("SEC-1");
    expect(result.ticketUrl).toContain("linear.app");
  });

  it("handles API error gracefully", async () => {
    (globalThis.fetch as any).mockRejectedValue(new Error("timeout"));
    const result = await pushFindingToLinear(linearConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.reason).toContain("timeout");
  });

  it("handles non-ok response", async () => {
    (globalThis.fetch as any).mockResolvedValue({ ok: false, status: 401 });
    const result = await pushFindingToLinear(linearConfig, mockFinding, "https://target.com");
    expect(result.action).toBe("skipped");
    expect(result.reason).toContain("401");
  });
});

// ─── pushFindingsToTicketing (orchestrator) ──────────────────────────────────

describe("pushFindingsToTicketing", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns empty array for no integrations enabled", async () => {
    const results = await pushFindingsToTicketing({}, [mockFinding], "https://target.com");
    expect(results).toEqual([]);
  });

  it("returns empty array for empty findings", async () => {
    const results = await pushFindingsToTicketing(
      { github: { enabled: true, repo: "o/r", token: "t", minSeverity: "low" } },
      [],
      "https://target.com"
    );
    expect(results).toEqual([]);
  });

  it("calls multiple integrations for each finding in dry-run", async () => {
    const results = await pushFindingsToTicketing(
      {
        github: { enabled: true, repo: "o/r", token: "t", minSeverity: "low" },
        linear: { enabled: true, apiKey: "k", teamId: "t", minSeverity: "low" },
      },
      [mockFinding],
      "https://target.com",
      true,
    );
    expect(results).toHaveLength(2);
    expect(results[0].provider).toBe("github");
    expect(results[1].provider).toBe("linear");
    expect(results.every((r) => r.action === "created")).toBe(true);
  });

  it("processes multiple findings across integrations", async () => {
    const finding2: ScanFinding = { ...mockFinding, title: "XSS at /search", severity: "medium" };
    const results = await pushFindingsToTicketing(
      { linear: { enabled: true, apiKey: "k", teamId: "t", minSeverity: "low" } },
      [mockFinding, finding2],
      "https://target.com",
      true,
    );
    expect(results).toHaveLength(2);
    expect(results[0].findingTitle).toBe("SQL Injection at /api/users");
    expect(results[1].findingTitle).toBe("XSS at /search");
  });
});
