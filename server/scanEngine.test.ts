import { describe, it, expect } from "vitest";
import { analyzeAttackScenarios, computeTrend, calculateScore, isSpaFallback, hasFileSpecificContent, buildAuthHeader, profilePrivilegeRank, parseOsvOutput, parseTrivyOutput, scaVulnsToFindings, type AttackScenario, type TrendSummary, type AuthProfile, type ScaDependencyVuln } from "./scanEngine";

describe("analyzeAttackScenarios", () => {
  it("returns empty array when no findings", () => {
    expect(analyzeAttackScenarios([])).toEqual([]);
  });

  it("detects SQL Injection data exfiltration scenario", () => {
    const findings = [
      { category: "SQL Injection", title: "SQLi at /api/users?id=1" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-003");
    expect(match).toBeDefined();
    expect(match!.title).toBe("Data Exfiltration via SQL Injection");
    expect(match!.impact).toBe("High");
    expect(match!.steps).toHaveLength(1);
    expect(match!.steps[0].findingTitle).toBe("SQLi at /api/users?id=1");
  });

  it("detects Account Takeover when two Authentication findings exist", () => {
    const findings = [
      { category: "Authentication", title: "Account enumeration via login" },
      { category: "Authentication", title: "No brute force protection" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-001");
    expect(match).toBeDefined();
    expect(match!.title).toBe("Account Takeover via Brute Force");
    expect(match!.steps).toHaveLength(2);
  });

  it("detects Session Hijack when XSS + CORS findings exist", () => {
    const findings = [
      { category: "Cross-Site Scripting", title: "Reflected XSS at /search" },
      { category: "CORS", title: "Permissive CORS policy" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-002");
    expect(match).toBeDefined();
    expect(match!.title).toBe("Session Hijack via XSS and CORS");
    expect(match!.likelihood).toBe("Medium");
    expect(match!.impact).toBe("High");
  });

  it("detects Path Traversal file access scenario", () => {
    const findings = [
      { category: "Path Traversal", title: "Directory traversal at /download" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-004");
    expect(match).toBeDefined();
    expect(match!.title).toBe("Unauthorised File Access via Traversal");
  });

  it("detects XSS + missing CSP scenario", () => {
    const findings = [
      { category: "Cross-Site Scripting", title: "Stored XSS" },
      { category: "Security Headers", title: "Missing CSP" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-005");
    expect(match).toBeDefined();
    expect(match!.title).toBe("XSS-based Account Compromise");
  });

  it("detects Information Disclosure credential exposure", () => {
    const findings = [
      { category: "Information Disclosure", title: ".env file exposed" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-006");
    expect(match).toBeDefined();
  });

  it("detects TLS man-in-the-middle scenario", () => {
    const findings = [
      { category: "TLS", title: "TLS 1.0 supported" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-007");
    expect(match).toBeDefined();
    expect(match!.title).toBe("Man-in-the-Middle via Weak TLS");
  });

  it("does not produce scenarios when required categories are missing", () => {
    const findings = [
      { category: "Security Headers", title: "Missing X-Frame-Options" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const accountTakeover = scenarios.find((s) => s.id === "S-001");
    const sessionHijack = scenarios.find((s) => s.id === "S-002");
    const sqli = scenarios.find((s) => s.id === "S-003");
    expect(accountTakeover).toBeUndefined();
    expect(sessionHijack).toBeUndefined();
    expect(sqli).toBeUndefined();
  });

  it("returns multiple scenarios when findings match multiple templates", () => {
    const findings = [
      { category: "SQL Injection", title: "SQLi" },
      { category: "Cross-Site Scripting", title: "XSS" },
      { category: "CORS", title: "CORS misconfiguration" },
      { category: "Security Headers", title: "Missing CSP" },
      { category: "Path Traversal", title: "Traversal" },
      { category: "TLS", title: "Weak TLS" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    expect(scenarios.length).toBeGreaterThanOrEqual(5);
    expect(scenarios.map((s) => s.id)).toContain("S-002");
    expect(scenarios.map((s) => s.id)).toContain("S-003");
    expect(scenarios.map((s) => s.id)).toContain("S-004");
    expect(scenarios.map((s) => s.id)).toContain("S-005");
    expect(scenarios.map((s) => s.id)).toContain("S-007");
  });

  it("each scenario has the expected structure", () => {
    const findings = [
      { category: "SQL Injection", title: "SQLi at /api" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    for (const s of scenarios) {
      expect(s.id).toMatch(/^S-\d{3}$/);
      expect(s.title).toBeTruthy();
      expect(s.objective).toBeTruthy();
      expect(s.steps.length).toBeGreaterThan(0);
      expect(["High", "Medium", "Low"]).toContain(s.likelihood);
      expect(["High", "Medium", "Low"]).toContain(s.impact);
      for (const step of s.steps) {
        expect(step.findingTitle).toBeTruthy();
        expect(step.role).toBeTruthy();
      }
    }
  });
});

describe("computeTrend", () => {
  const prevScan = { id: 1, completedAt: new Date("2025-06-01T00:00:00Z") };

  it("identifies all findings as new when no previous findings", () => {
    const current = [
      { title: "Missing CSP", category: "Security Headers", severity: "medium" as const },
      { title: "No rate limiting", category: "Authentication", severity: "high" as const },
    ];
    const trend = computeTrend(current, [], prevScan);
    expect(trend.newFindings).toBe(2);
    expect(trend.resolvedFindings).toBe(0);
    expect(trend.persistingFindings).toBe(0);
    expect(trend.newItems).toContain("Missing CSP");
    expect(trend.newItems).toContain("No rate limiting");
  });

  it("identifies all previous findings as resolved when none persist", () => {
    const prev = [
      { title: "Old vuln", category: "SQL Injection", severity: "critical" },
    ];
    const trend = computeTrend([], prev, prevScan);
    expect(trend.newFindings).toBe(0);
    expect(trend.resolvedFindings).toBe(1);
    expect(trend.persistingFindings).toBe(0);
    expect(trend.resolvedItems).toContain("Old vuln");
  });

  it("correctly classifies new, resolved, and persisting", () => {
    const prev = [
      { title: "Missing CSP", category: "Security Headers", severity: "medium" },
      { title: "Old SQLi", category: "SQL Injection", severity: "critical" },
    ];
    const current = [
      { title: "Missing CSP", category: "Security Headers", severity: "medium" as const },
      { title: "New XSS", category: "Cross-Site Scripting", severity: "high" as const },
    ];
    const trend = computeTrend(current, prev, prevScan);
    expect(trend.newFindings).toBe(1);
    expect(trend.resolvedFindings).toBe(1);
    expect(trend.persistingFindings).toBe(1);
    expect(trend.newItems).toContain("New XSS");
    expect(trend.resolvedItems).toContain("Old SQLi");
    expect(trend.persistingItems).toContain("Missing CSP");
  });

  it("includes previous scan metadata", () => {
    const trend = computeTrend([], [], prevScan);
    expect(trend.previousScanId).toBe(1);
    expect(trend.previousScanDate).toBe("2025-06-01");
  });

  it("handles duplicate findings (same title/category)", () => {
    const current = [
      { title: "Missing CSP", category: "Security Headers", severity: "medium" as const },
      { title: "Missing CSP", category: "Security Headers", severity: "medium" as const },
    ];
    const trend = computeTrend(current, [], prevScan);
    expect(trend.newItems).toHaveLength(1);
  });

  it("treats same title in different categories as different findings", () => {
    const prev = [
      { title: "Test finding", category: "CategoryA", severity: "low" },
    ];
    const current = [
      { title: "Test finding", category: "CategoryB", severity: "low" as const },
    ];
    const trend = computeTrend(current, prev, prevScan);
    expect(trend.newFindings).toBe(1);
    expect(trend.resolvedFindings).toBe(1);
    expect(trend.persistingFindings).toBe(0);
  });

  it("handles null completedAt gracefully", () => {
    const prevNull = { id: 5, completedAt: null };
    const trend = computeTrend([], [], prevNull);
    expect(trend.previousScanDate).toBe("unknown");
  });
});

describe("analyzeAttackScenarios — Phase 3 templates", () => {
  it("detects Business Logic privilege escalation scenario", () => {
    const findings = [
      { category: "Business Logic", title: "Mass assignment at /api/users" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-008");
    expect(match).toBeDefined();
    expect(match!.title).toBe("Privilege Escalation via Mass Assignment");
    expect(match!.impact).toBe("High");
  });

  it("detects GraphQL introspection enumeration scenario", () => {
    const findings = [
      { category: "GraphQL", title: "Introspection enabled" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-009");
    expect(match).toBeDefined();
    expect(match!.title).toBe("API Enumeration via GraphQL Introspection");
    expect(match!.likelihood).toBe("High");
    expect(match!.impact).toBe("Medium");
  });

  it("includes new scenarios alongside existing ones", () => {
    const findings = [
      { category: "SQL Injection", title: "SQLi" },
      { category: "Business Logic", title: "Debug endpoint" },
      { category: "GraphQL", title: "Introspection" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    expect(scenarios.map((s) => s.id)).toContain("S-003");
    expect(scenarios.map((s) => s.id)).toContain("S-008");
    expect(scenarios.map((s) => s.id)).toContain("S-009");
  });
});

describe("calculateScore", () => {
  it("returns 100 and info for empty findings", () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe("info");
  });

  it("deducts 22 per critical, capped at 2", () => {
    const findings = [{ severity: "critical" as const }, { severity: "critical" as const }];
    expect(calculateScore(findings).score).toBe(56); // 100 - 44
  });

  it("caps critical deductions at maxCount 2", () => {
    const findings = Array(5).fill({ severity: "critical" as const });
    expect(calculateScore(findings).score).toBe(56); // only 2 counted
  });

  it("deducts 12 per high, capped at 3", () => {
    const findings = [{ severity: "high" as const }, { severity: "high" as const }, { severity: "high" as const }];
    expect(calculateScore(findings).score).toBe(64); // 100 - 36
  });

  it("caps high deductions at maxCount 3", () => {
    const findings = Array(6).fill({ severity: "high" as const });
    expect(calculateScore(findings).score).toBe(64); // only 3 counted
  });

  it("deducts 5 per medium, capped at 6", () => {
    const findings = Array(6).fill({ severity: "medium" as const });
    expect(calculateScore(findings).score).toBe(70); // 100 - 30
  });

  it("deducts 2 per low, capped at 5", () => {
    const findings = Array(5).fill({ severity: "low" as const });
    expect(calculateScore(findings).score).toBe(90); // 100 - 10
  });

  it("deducts 0.5 per info, capped at 5", () => {
    const findings = Array(5).fill({ severity: "info" as const });
    expect(calculateScore(findings).score).toBe(98); // 100 - 2.5 → rounds to 98
  });

  it("floors score at 0", () => {
    const findings = [
      ...Array(2).fill({ severity: "critical" as const }),
      ...Array(3).fill({ severity: "high" as const }),
      ...Array(6).fill({ severity: "medium" as const }),
    ];
    // 100 - 44 - 36 - 30 = -10 → floored to 0
    expect(calculateScore(findings).score).toBe(0);
  });

  it("returns critical riskLevel for score < 40", () => {
    const findings = Array(2).fill({ severity: "critical" as const });
    // score = 56, not critical
    const big = [
      ...Array(2).fill({ severity: "critical" as const }),
      ...Array(3).fill({ severity: "high" as const }),
    ];
    // 100 - 44 - 36 = 20 → critical
    expect(calculateScore(big).riskLevel).toBe("critical");
  });

  it("returns high riskLevel for score 40-59", () => {
    const findings = Array(2).fill({ severity: "critical" as const });
    // 100 - 44 = 56
    expect(calculateScore(findings).riskLevel).toBe("high");
  });

  it("returns medium riskLevel for score 60-74", () => {
    const findings = Array(3).fill({ severity: "high" as const });
    // 100 - 36 = 64
    expect(calculateScore(findings).riskLevel).toBe("medium");
  });

  it("returns low riskLevel for score 75-89", () => {
    const findings = Array(3).fill({ severity: "medium" as const });
    // 100 - 15 = 85
    expect(calculateScore(findings).riskLevel).toBe("low");
  });

  it("returns info riskLevel for score >= 90", () => {
    const findings = [{ severity: "low" as const }];
    // 100 - 2 = 98
    expect(calculateScore(findings).riskLevel).toBe("info");
  });

  it("handles mixed severities correctly", () => {
    const findings = [
      { severity: "critical" as const },
      { severity: "high" as const },
      { severity: "medium" as const },
      { severity: "low" as const },
      { severity: "info" as const },
    ];
    // 100 - 22 - 12 - 5 - 2 - 0.5 = 58.5 → rounds to 59
    expect(calculateScore(findings).score).toBe(59);
    expect(calculateScore(findings).riskLevel).toBe("high");
  });
});

describe("isSpaFallback", () => {
  it("returns true for text/html with <!doctype html>", () => {
    expect(isSpaFallback("<!doctype html><html><body>App</body></html>", "text/html")).toBe(true);
  });

  it("returns true for text/html with <html>", () => {
    expect(isSpaFallback("<html><body>React app</body></html>", "text/html; charset=utf-8")).toBe(true);
  });

  it("returns true for <!DOCTYPE HTML> (case insensitive body)", () => {
    expect(isSpaFallback("<!DOCTYPE HTML><html>", "text/html")).toBe(true);
  });

  it("returns false for text/html with non-HTML content", () => {
    expect(isSpaFallback("API_KEY=secret\nDB=prod", "text/html")).toBe(false);
  });

  it("returns false for non-HTML content type", () => {
    expect(isSpaFallback("<!doctype html>", "text/plain")).toBe(false);
  });

  it("returns false for application/json", () => {
    expect(isSpaFallback('{"key":"value"}', "application/json")).toBe(false);
  });

  it("returns false for empty content type", () => {
    expect(isSpaFallback("<!doctype html>", "")).toBe(false);
  });

  it("handles whitespace in body", () => {
    expect(isSpaFallback("  \n  <!doctype html><html>", "text/html")).toBe(true);
  });

  it("returns false for empty body", () => {
    expect(isSpaFallback("", "text/html")).toBe(false);
  });
});

describe("hasFileSpecificContent", () => {
  it("returns true for .env with KEY=value pattern", () => {
    expect(hasFileSpecificContent("/.env", "API_KEY=secret\nDB_HOST=localhost")).toBe(true);
  });

  it("returns false for .env with HTML content (SPA fallback)", () => {
    expect(hasFileSpecificContent("/.env", "<!doctype html><html><body>Not found</body></html>")).toBe(false);
  });

  it("returns true for .git/config with [core]", () => {
    expect(hasFileSpecificContent("/.git/config", "[core]\nrepositoryformatversion = 0")).toBe(true);
  });

  it("returns true for .git/config with [remote]", () => {
    expect(hasFileSpecificContent("/.git/config", "[remote]\nurl = git@github.com:user/repo")).toBe(true);
  });

  it("returns false for .git/config with HTML content", () => {
    expect(hasFileSpecificContent("/.git/config", "<!doctype html><html>404</html>")).toBe(false);
  });

  it("returns true for phpinfo with PHP Version", () => {
    expect(hasFileSpecificContent("/phpinfo.php", "<html>PHP Version 8.2.0</html>")).toBe(true);
  });

  it("returns true for phpinfo with phpinfo()", () => {
    expect(hasFileSpecificContent("/phpinfo.php", "phpinfo() output")).toBe(true);
  });

  it("returns true for phpinfo with Configuration", () => {
    expect(hasFileSpecificContent("/phpinfo.php", "Configuration File Path")).toBe(true);
  });

  it("returns true for wp-admin with wordpress", () => {
    expect(hasFileSpecificContent("/wp-admin/", "<html>wordpress login</html>")).toBe(true);
  });

  it("returns true for wp-admin with wp-login", () => {
    expect(hasFileSpecificContent("/wp-admin/", "wp-login form")).toBe(true);
  });

  it("returns false for unknown path", () => {
    expect(hasFileSpecificContent("/unknown-path", "random content")).toBe(false);
  });

  it("returns false for unknown path with KEY=value (not .env)", () => {
    expect(hasFileSpecificContent("/random", "API_KEY=secret")).toBe(false);
  });

  it("handles paths with query strings", () => {
    expect(hasFileSpecificContent("/.env.bak", "SECRET_KEY=abc123")).toBe(true);
  });
});

// ─── buildAuthHeader ─────────────────────────────────────────────────────────

describe("buildAuthHeader", () => {
  it("returns Bearer header for bearer type", () => {
    const profile: AuthProfile = { name: "admin", type: "bearer", token: "eyJabc123" };
    expect(buildAuthHeader(profile)).toEqual({ Authorization: "Bearer eyJabc123" });
  });

  it("returns empty object for bearer without token", () => {
    const profile: AuthProfile = { name: "admin", type: "bearer" };
    expect(buildAuthHeader(profile)).toEqual({});
  });

  it("returns Basic header for basic type", () => {
    const profile: AuthProfile = { name: "user", type: "basic", username: "admin", password: "secret" };
    const expected = Buffer.from("admin:secret").toString("base64");
    expect(buildAuthHeader(profile)).toEqual({ Authorization: `Basic ${expected}` });
  });

  it("returns Basic header with empty password", () => {
    const profile: AuthProfile = { name: "user", type: "basic", username: "admin" };
    const expected = Buffer.from("admin:").toString("base64");
    expect(buildAuthHeader(profile)).toEqual({ Authorization: `Basic ${expected}` });
  });

  it("returns empty object for basic without username", () => {
    const profile: AuthProfile = { name: "user", type: "basic" };
    expect(buildAuthHeader(profile)).toEqual({});
  });

  it("returns empty object for none type", () => {
    const profile: AuthProfile = { name: "anon", type: "none" };
    expect(buildAuthHeader(profile)).toEqual({});
  });
});

// ─── profilePrivilegeRank ─────────────────────────────────────────────────────

describe("profilePrivilegeRank", () => {
  it("returns 0 for anonymous profile", () => {
    expect(profilePrivilegeRank({ name: "anonymous", type: "none" })).toBe(0);
  });

  it("returns 0 for any 'none' type regardless of name", () => {
    expect(profilePrivilegeRank({ name: "whatever", type: "none" })).toBe(0);
  });

  it("returns 1 for read-only profiles", () => {
    expect(profilePrivilegeRank({ name: "read_only", type: "bearer", token: "x" })).toBe(1);
    expect(profilePrivilegeRank({ name: "viewer", type: "bearer", token: "x" })).toBe(1);
  });

  it("returns 2 for standard user profiles", () => {
    expect(profilePrivilegeRank({ name: "standard_user", type: "bearer", token: "x" })).toBe(2);
    expect(profilePrivilegeRank({ name: "user", type: "bearer", token: "x" })).toBe(2);
    expect(profilePrivilegeRank({ name: "member", type: "bearer", token: "x" })).toBe(2);
  });

  it("returns 3 for editor/manager profiles", () => {
    expect(profilePrivilegeRank({ name: "editor", type: "bearer", token: "x" })).toBe(3);
    expect(profilePrivilegeRank({ name: "manager", type: "bearer", token: "x" })).toBe(3);
  });

  it("returns 4 for admin profiles", () => {
    expect(profilePrivilegeRank({ name: "admin", type: "bearer", token: "x" })).toBe(4);
    expect(profilePrivilegeRank({ name: "superadmin", type: "bearer", token: "x" })).toBe(4);
    expect(profilePrivilegeRank({ name: "root", type: "bearer", token: "x" })).toBe(4);
  });

  it("defaults to 2 for unrecognized names", () => {
    expect(profilePrivilegeRank({ name: "custom_role", type: "bearer", token: "x" })).toBe(2);
  });
});

// ─── Attack Scenario Templates (S-010, S-011) ────────────────────────────────

describe("analyzeAttackScenarios — auth scenarios", () => {
  it("detects S-010 privilege escalation via Authorization findings", () => {
    const findings = [
      { category: "Authorization", title: "Vertical Privilege Escalation — /api/admin accessible as user" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-010");
    expect(match).toBeDefined();
    expect(match!.title).toContain("Privilege Escalation");
  });

  it("detects S-011 IDOR data theft with Authorization + Information Disclosure", () => {
    const findings = [
      { category: "Authorization", title: "Horizontal escalation at /api/users/1" },
      { category: "Information Disclosure", title: "Exposed user data" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-011");
    expect(match).toBeDefined();
    expect(match!.title).toContain("IDOR");
  });

  it("does not trigger S-011 without Information Disclosure", () => {
    const findings = [
      { category: "Authorization", title: "Horizontal escalation" },
    ];
    const scenarios = analyzeAttackScenarios(findings);
    const match = scenarios.find((s) => s.id === "S-011");
    expect(match).toBeUndefined();
  });
});

// ─── parseOsvOutput ──────────────────────────────────────────────────────────

describe("parseOsvOutput", () => {
  it("parses valid OSV-Scanner JSON output", () => {
    const json = JSON.stringify({
      results: [{
        packages: [{
          package: { name: "lodash", version: "4.17.20" },
          vulnerabilities: [{
            id: "GHSA-xxxx",
            aliases: ["CVE-2021-23337"],
            summary: "Prototype pollution in lodash",
            database_specific: { severity: "HIGH" },
            affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
          }],
        }],
      }],
    });
    const vulns = parseOsvOutput(json);
    expect(vulns).toHaveLength(1);
    expect(vulns[0].package).toBe("lodash");
    expect(vulns[0].installedVersion).toBe("4.17.20");
    expect(vulns[0].fixedVersion).toBe("4.17.21");
    expect(vulns[0].cve).toBe("CVE-2021-23337");
    expect(vulns[0].severity).toBe("high");
  });

  it("returns empty array for malformed JSON", () => {
    expect(parseOsvOutput("not json")).toEqual([]);
  });

  it("returns empty array for empty results", () => {
    expect(parseOsvOutput(JSON.stringify({ results: [] }))).toEqual([]);
  });

  it("handles missing fixed version", () => {
    const json = JSON.stringify({
      results: [{
        packages: [{
          package: { name: "pkg", version: "1.0.0" },
          vulnerabilities: [{
            id: "GHSA-yyyy",
            aliases: ["CVE-2023-1234"],
            summary: "Some vuln",
            database_specific: { severity: "CRITICAL" },
          }],
        }],
      }],
    });
    const vulns = parseOsvOutput(json);
    expect(vulns[0].fixedVersion).toBeNull();
    expect(vulns[0].severity).toBe("critical");
  });
});

// ─── parseTrivyOutput ────────────────────────────────────────────────────────

describe("parseTrivyOutput", () => {
  it("parses valid Trivy JSON output", () => {
    const json = JSON.stringify({
      Results: [{
        Vulnerabilities: [{
          VulnerabilityID: "CVE-2022-42003",
          PkgName: "jackson-databind",
          InstalledVersion: "2.13.0",
          FixedVersion: "2.13.4.2",
          Severity: "HIGH",
          Title: "Uncontrolled Resource Consumption",
        }],
      }],
    });
    const vulns = parseTrivyOutput(json);
    expect(vulns).toHaveLength(1);
    expect(vulns[0].package).toBe("jackson-databind");
    expect(vulns[0].cve).toBe("CVE-2022-42003");
    expect(vulns[0].severity).toBe("high");
    expect(vulns[0].fixedVersion).toBe("2.13.4.2");
  });

  it("returns empty array for malformed JSON", () => {
    expect(parseTrivyOutput("bad json")).toEqual([]);
  });

  it("handles missing severity", () => {
    const json = JSON.stringify({
      Results: [{
        Vulnerabilities: [{
          VulnerabilityID: "CVE-2023-9999",
          PkgName: "some-lib",
          InstalledVersion: "1.0",
        }],
      }],
    });
    const vulns = parseTrivyOutput(json);
    expect(vulns[0].severity).toBe("medium");
  });
});

// ─── scaVulnsToFindings ──────────────────────────────────────────────────────

describe("scaVulnsToFindings", () => {
  it("converts SCA vulns to findings with correct fields", () => {
    const vulns: ScaDependencyVuln[] = [{
      package: "express",
      installedVersion: "4.17.1",
      fixedVersion: "4.18.0",
      cve: "CVE-2024-1234",
      severity: "high",
      summary: "Prototype pollution",
    }];
    const findings = scaVulnsToFindings(vulns, "npm");
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe("SCA");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("express");
    expect(findings[0].title).toContain("CVE-2024-1234");
    expect(findings[0].cweId).toBe("CWE-1104");
    expect(findings[0].owaspCategory).toBe("A06:2021 – Vulnerable and Outdated Components");
    expect(findings[0].recommendation).toContain("4.18.0");
  });

  it("handles missing fixed version", () => {
    const vulns: ScaDependencyVuln[] = [{
      package: "old-lib",
      installedVersion: "0.1.0",
      fixedVersion: null,
      cve: "CVE-2020-5555",
      severity: "critical",
      summary: "RCE vulnerability",
    }];
    const findings = scaVulnsToFindings(vulns, "PyPI");
    expect(findings[0].description).toContain("No fixed version available");
    expect(findings[0].recommendation).toContain("alternative packages");
  });
});
