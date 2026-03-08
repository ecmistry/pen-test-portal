import { describe, it, expect, vi } from "vitest";
import { analyzeAttackScenarios, computeTrend, calculateScore, isSpaFallback, hasFileSpecificContent, buildAuthHeader, profilePrivilegeRank, parseOsvOutput, parseTrivyOutput, scaVulnsToFindings, performLogin, extractCookies, mergeCookies, isNiktoMetadataLine, isNiktoLegacyCGI, getToolAuthCapabilities, testURLNormalisationBypass, type AttackScenario, type TrendSummary, type AuthProfile, type ScaDependencyVuln, type LoginCredentials, type ScanAuthMeta } from "./scanEngine";

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

// ─── extractCookies ──────────────────────────────────────────────────────────

describe("extractCookies", () => {
  it("returns empty string when no set-cookie header", () => {
    expect(extractCookies({})).toBe("");
    expect(extractCookies({ "content-type": "text/html" })).toBe("");
  });

  it("extracts a single cookie (strips attributes)", () => {
    const headers = { "set-cookie": "session=abc123; Path=/; HttpOnly" };
    expect(extractCookies(headers)).toBe("session=abc123");
  });

  it("extracts multiple cookies from array", () => {
    const headers = { "set-cookie": ["session=abc123; Path=/", "csrftoken=xyz; Secure"] as any };
    const result = extractCookies(headers);
    expect(result).toContain("session=abc123");
    expect(result).toContain("csrftoken=xyz");
    expect(result).toBe("session=abc123; csrftoken=xyz");
  });

  it("handles undefined values in array gracefully", () => {
    const headers = { "set-cookie": [undefined, "a=1; Path=/"] as any };
    expect(extractCookies(headers)).toBe("a=1");
  });
});

// ─── mergeCookies ────────────────────────────────────────────────────────────

describe("mergeCookies", () => {
  it("merges two disjoint cookie strings", () => {
    const result = mergeCookies("a=1", "b=2");
    expect(result).toContain("a=1");
    expect(result).toContain("b=2");
  });

  it("overwrites cookies with same name", () => {
    const result = mergeCookies("session=old", "session=new");
    expect(result).toBe("session=new");
    expect(result).not.toContain("old");
  });

  it("handles empty strings", () => {
    expect(mergeCookies("", "a=1")).toBe("a=1");
    expect(mergeCookies("a=1", "")).toBe("a=1");
    expect(mergeCookies("", "")).toBe("");
  });

  it("preserves multiple cookies with overwrites", () => {
    const result = mergeCookies("a=1; b=2; c=3", "b=updated; d=4");
    expect(result).toContain("a=1");
    expect(result).toContain("b=updated");
    expect(result).toContain("c=3");
    expect(result).toContain("d=4");
    expect(result).not.toContain("b=2");
  });
});

// ─── LoginCredentials type ────────────────────────────────────────────────────

describe("LoginCredentials type", () => {
  it("has the expected shape", () => {
    const creds: LoginCredentials = {
      loginUrl: "https://example.com/login",
      username: "admin",
      password: "secret",
      usernameField: "email",
      passwordField: "pass",
      loginMethod: "json",
    };
    expect(creds.loginUrl).toBe("https://example.com/login");
    expect(creds.loginMethod).toBe("json");
  });

  it("allows optional fields to be undefined", () => {
    const creds: LoginCredentials = {
      loginUrl: "https://example.com/login",
      username: "admin",
      password: "secret",
    };
    expect(creds.usernameField).toBeUndefined();
    expect(creds.passwordField).toBeUndefined();
    expect(creds.loginMethod).toBeUndefined();
  });
});

// ─── extractCookies edge cases ───────────────────────────────────────────────

describe("extractCookies — edge cases", () => {
  it("strips Path, Domain, Secure, HttpOnly attributes", () => {
    const result = extractCookies({ "set-cookie": "sid=abc; Path=/; Domain=.example.com; Secure; HttpOnly" });
    expect(result).toBe("sid=abc");
  });

  it("handles cookie with = in value", () => {
    const result = extractCookies({ "set-cookie": "token=abc=def==; Path=/" });
    expect(result).toBe("token=abc=def==");
  });

  it("handles set-cookie with empty string", () => {
    const result = extractCookies({ "set-cookie": "" });
    expect(result).toBe("");
  });
});

// ─── mergeCookies edge cases ─────────────────────────────────────────────────

describe("mergeCookies — edge cases", () => {
  it("handles cookie with = in value", () => {
    const result = mergeCookies("token=abc=123", "session=xyz");
    expect(result).toContain("token=abc=123");
    expect(result).toContain("session=xyz");
  });

  it("handles single cookie without value", () => {
    const result = mergeCookies("flagonly", "a=1");
    expect(result).toContain("flagonly");
    expect(result).toContain("a=1");
  });

  it("overwrites when merging same name with different values", () => {
    const result = mergeCookies("a=1; b=2", "a=new; c=3");
    expect(result).toContain("a=new");
    expect(result).toContain("b=2");
    expect(result).toContain("c=3");
    expect(result).not.toContain("a=1");
  });
});

// ─── parseOsvOutput edge cases ───────────────────────────────────────────────

describe("parseOsvOutput — edge cases", () => {
  it("handles multiple vulnerabilities for same package", () => {
    const output = JSON.stringify({
      results: [{
        source: { path: "package.json" },
        packages: [{
          package: { name: "lodash", version: "4.17.15" },
          vulnerabilities: [
            { id: "CVE-2020-8203", summary: "Prototype Pollution", database_specific: { severity: "HIGH" } },
            { id: "CVE-2021-23337", summary: "Command Injection", database_specific: { severity: "CRITICAL" } },
          ],
        }],
      }],
    });
    const vulns = parseOsvOutput(output);
    expect(vulns).toHaveLength(2);
    expect(vulns[0].cve).toBe("CVE-2020-8203");
    expect(vulns[1].cve).toBe("CVE-2021-23337");
    expect(vulns[1].severity).toBe("critical");
  });

  it("handles multiple packages in results", () => {
    const output = JSON.stringify({
      results: [{
        source: { path: "package.json" },
        packages: [
          { package: { name: "express", version: "4.17.0" }, vulnerabilities: [{ id: "CVE-2024-1111", summary: "XSS", database_specific: { severity: "MEDIUM" } }] },
          { package: { name: "axios", version: "0.21.0" }, vulnerabilities: [{ id: "CVE-2024-2222", summary: "SSRF", database_specific: { severity: "HIGH" } }] },
        ],
      }],
    });
    const vulns = parseOsvOutput(output);
    expect(vulns).toHaveLength(2);
    expect(vulns[0].package).toBe("express");
    expect(vulns[1].package).toBe("axios");
  });

  it("handles empty results array", () => {
    const vulns = parseOsvOutput(JSON.stringify({ results: [] }));
    expect(vulns).toEqual([]);
  });
});

// ─── parseTrivyOutput edge cases ─────────────────────────────────────────────

describe("parseTrivyOutput — edge cases", () => {
  it("handles multiple Results entries", () => {
    const output = JSON.stringify({
      Results: [
        {
          Target: "package.json",
          Vulnerabilities: [{ VulnerabilityID: "CVE-2024-0001", PkgName: "a", InstalledVersion: "1.0", FixedVersion: "1.1", Severity: "HIGH", Title: "Bug A" }],
        },
        {
          Target: "go.mod",
          Vulnerabilities: [{ VulnerabilityID: "CVE-2024-0002", PkgName: "b", InstalledVersion: "2.0", FixedVersion: "2.1", Severity: "LOW", Title: "Bug B" }],
        },
      ],
    });
    const vulns = parseTrivyOutput(output);
    expect(vulns).toHaveLength(2);
    expect(vulns[0].package).toBe("a");
    expect(vulns[1].package).toBe("b");
  });

  it("handles empty Results array", () => {
    const vulns = parseTrivyOutput(JSON.stringify({ Results: [] }));
    expect(vulns).toEqual([]);
  });

  it("handles null Vulnerabilities in a Result", () => {
    const output = JSON.stringify({
      Results: [{ Target: "package.json", Vulnerabilities: null }],
    });
    const vulns = parseTrivyOutput(output);
    expect(vulns).toEqual([]);
  });
});

// ─── scaVulnsToFindings edge cases ───────────────────────────────────────────

describe("scaVulnsToFindings — edge cases", () => {
  it("returns empty array for empty vulns", () => {
    expect(scaVulnsToFindings([], "npm")).toEqual([]);
  });

  it("handles different ecosystem names", () => {
    const vulns: ScaDependencyVuln[] = [{
      package: "django",
      installedVersion: "3.2.0",
      fixedVersion: "3.2.1",
      cve: "CVE-2024-9999",
      severity: "medium",
      summary: "XSS flaw",
    }];
    const findings = scaVulnsToFindings(vulns, "PyPI");
    expect(findings[0].title).toContain("django");
    expect(findings[0].title).toContain("CVE-2024-9999");
    expect(findings[0].description).toContain("PyPI");
  });

  it("produces multiple findings for multiple vulns", () => {
    const vulns: ScaDependencyVuln[] = [
      { package: "a", installedVersion: "1.0", fixedVersion: "1.1", cve: "CVE-1", severity: "high", summary: "X" },
      { package: "b", installedVersion: "2.0", fixedVersion: "2.1", cve: "CVE-2", severity: "low", summary: "Y" },
      { package: "c", installedVersion: "3.0", fixedVersion: null, cve: "CVE-3", severity: "critical", summary: "Z" },
    ];
    const findings = scaVulnsToFindings(vulns, "npm");
    expect(findings).toHaveLength(3);
    expect(findings[0].severity).toBe("high");
    expect(findings[2].severity).toBe("critical");
  });
});

// ─── calculateScore edge cases ───────────────────────────────────────────────

describe("calculateScore — additional edge cases", () => {
  it("caps deductions at maxCount per severity", () => {
    const manyHighs = Array.from({ length: 20 }, () => ({ severity: "high" as const }));
    const result = calculateScore(manyHighs);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });

  it("returns info risk level for score 100", () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe("info");
  });

  it("never goes below 0", () => {
    const extreme = [
      ...Array.from({ length: 10 }, () => ({ severity: "critical" as const })),
      ...Array.from({ length: 10 }, () => ({ severity: "high" as const })),
    ];
    const result = calculateScore(extreme);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });
});

// ─── computeTrend edge cases ─────────────────────────────────────────────────

describe("computeTrend — additional edge cases", () => {
  it("all findings are resolved (none persist)", () => {
    const previous = [
      { title: "Old Bug", category: "Auth", severity: "high" },
    ];
    const current = [] as { title: string; category: string; severity: string }[];
    const trend = computeTrend(current, previous, { id: 1, completedAt: new Date() });
    expect(trend.resolvedFindings).toBe(1);
    expect(trend.newFindings).toBe(0);
    expect(trend.persistingFindings).toBe(0);
  });

  it("all findings are new (none existed before)", () => {
    const current = [
      { title: "New Bug A", category: "XSS", severity: "medium" },
      { title: "New Bug B", category: "SQLi", severity: "high" },
    ];
    const previous = [] as { title: string; category: string; severity: string }[];
    const trend = computeTrend(current, previous, { id: 1, completedAt: new Date() });
    expect(trend.newFindings).toBe(2);
    expect(trend.resolvedFindings).toBe(0);
    expect(trend.persistingFindings).toBe(0);
  });

  it("captures previousAuthMode from previous scan", () => {
    const trend = computeTrend([], [], { id: 5, completedAt: new Date(), authMode: "authenticated" });
    expect(trend.previousAuthMode).toBe("authenticated");
  });

  it("previousAuthMode is undefined when previous scan has no authMode", () => {
    const trend = computeTrend([], [], { id: 5, completedAt: new Date() });
    expect(trend.previousAuthMode).toBeUndefined();
  });
});

// ─── isNiktoMetadataLine ─────────────────────────────────────────────────────

describe("isNiktoMetadataLine", () => {
  it("identifies Target IP line", () => {
    expect(isNiktoMetadataLine("+ Target IP: 1.2.3.4")).toBe(true);
  });

  it("identifies Target Hostname line", () => {
    expect(isNiktoMetadataLine("+ Target Hostname: example.com")).toBe(true);
  });

  it("identifies Target Port line", () => {
    expect(isNiktoMetadataLine("+ Target Port: 443")).toBe(true);
  });

  it("identifies Start Time line", () => {
    expect(isNiktoMetadataLine("+ Start Time: 2025-01-01 10:00:00")).toBe(true);
  });

  it("identifies End Time line", () => {
    expect(isNiktoMetadataLine("+ End Time: 2025-01-01 10:05:00")).toBe(true);
  });

  it("identifies SSL Info line", () => {
    expect(isNiktoMetadataLine("+ SSL Info: Subject: /CN=example.com")).toBe(true);
  });

  it("identifies Server line", () => {
    expect(isNiktoMetadataLine("+ Server: Apache/2.4.41")).toBe(true);
  });

  it("identifies hosts tested line", () => {
    expect(isNiktoMetadataLine("+ 1 host(s) tested")).toBe(true);
  });

  it("identifies Nikto version line", () => {
    expect(isNiktoMetadataLine("+ Nikto v2.5.0")).toBe(true);
  });

  it("identifies separator line", () => {
    expect(isNiktoMetadataLine("+ ---------------------------------------------------------------------------")).toBe(true);
  });

  it("does NOT classify OSVDB finding as metadata", () => {
    expect(isNiktoMetadataLine("+ OSVDB-3092: /admin/: This might be interesting.")).toBe(false);
  });

  it("does NOT classify general finding as metadata", () => {
    expect(isNiktoMetadataLine("+ /login.php: A login page was found.")).toBe(false);
  });
});

// ─── isNiktoLegacyCGI ────────────────────────────────────────────────────────

describe("isNiktoLegacyCGI", () => {
  it("identifies .cgi paths", () => {
    expect(isNiktoLegacyCGI("+ OSVDB-999: /cgi-bin/test-cgi: Test CGI found")).toBe(true);
  });

  it("identifies .exe paths", () => {
    expect(isNiktoLegacyCGI("+ OSVDB-101: /scripts/cart32.exe: Cart32 found")).toBe(true);
  });

  it("identifies classified.cgi", () => {
    expect(isNiktoLegacyCGI("+ OSVDB-333: /classified.cgi: Classified script")).toBe(true);
  });

  it("identifies IIS/FrontPage patterns", () => {
    expect(isNiktoLegacyCGI("+ OSVDB-444: /_vti_bin/shtml.dll: FrontPage")).toBe(true);
  });

  it("identifies .asp paths", () => {
    expect(isNiktoLegacyCGI("+ OSVDB-555: /default.asp: ASP page found")).toBe(true);
  });

  it("does NOT flag modern web paths", () => {
    expect(isNiktoLegacyCGI("+ OSVDB-3092: /admin/: Admin panel found")).toBe(false);
  });

  it("does NOT flag header findings", () => {
    expect(isNiktoLegacyCGI("+ The X-Content-Type-Options header is not set")).toBe(false);
  });

  it("does NOT flag SSL/TLS findings", () => {
    expect(isNiktoLegacyCGI("+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined")).toBe(false);
  });
});

// ─── hasFileSpecificContent expanded patterns ────────────────────────────────

describe("hasFileSpecificContent (expanded)", () => {
  it("returns true for .git/HEAD with ref:", () => {
    expect(hasFileSpecificContent("/.git/HEAD", "ref: refs/heads/main")).toBe(true);
  });

  it("returns true for .sql with CREATE TABLE", () => {
    expect(hasFileSpecificContent("/backup.sql", "CREATE TABLE users (id INT)")).toBe(true);
  });

  it("returns true for .sql with INSERT INTO", () => {
    expect(hasFileSpecificContent("/dump.sql", "INSERT INTO users VALUES (1, 'admin')")).toBe(true);
  });

  it("returns false for .sql with HTML", () => {
    expect(hasFileSpecificContent("/backup.sql", "<!doctype html><html>Not found</html>")).toBe(false);
  });

  it("returns true for .json with JSON content (non-HTML)", () => {
    expect(hasFileSpecificContent("/config.json", '{"database":"prod","port":3306}')).toBe(true);
  });

  it("returns false for .json with HTML (SPA fallback)", () => {
    expect(hasFileSpecificContent("/config.json", "<!doctype html><html>SPA</html>")).toBe(false);
  });

  it("returns true for .htaccess with RewriteRule", () => {
    expect(hasFileSpecificContent("/.htaccess", "RewriteRule ^(.*)$ index.php [L]")).toBe(true);
  });

  it("returns false for .htaccess with HTML", () => {
    expect(hasFileSpecificContent("/.htaccess", "<!doctype html><html>App</html>")).toBe(false);
  });

  it("returns true for .npmrc with registry", () => {
    expect(hasFileSpecificContent("/.npmrc", "registry=https://npm.pkg.github.com")).toBe(true);
  });

  it("returns true for docker-compose.yml (non-HTML)", () => {
    expect(hasFileSpecificContent("/docker-compose.yml", "version: '3'\nservices:\n  web:")).toBe(true);
  });

  it("returns false for docker-compose.yml with HTML", () => {
    expect(hasFileSpecificContent("/docker-compose.yml", "<!doctype html><html>SPA</html>")).toBe(false);
  });

  it("returns true for web.config with <configuration>", () => {
    expect(hasFileSpecificContent("/web.config", "<configuration><system.web>")).toBe(true);
  });
});

// ─── getToolAuthCapabilities ─────────────────────────────────────────────────

describe("getToolAuthCapabilities", () => {
  it("returns full support for headers", () => {
    const caps = getToolAuthCapabilities(["headers"]);
    expect(caps).toHaveLength(1);
    expect(caps[0].authSupport).toBe("full");
  });

  it("returns limited support for nikto", () => {
    const caps = getToolAuthCapabilities(["nikto"]);
    expect(caps[0].authSupport).toBe("limited");
  });

  it("returns none for tls", () => {
    const caps = getToolAuthCapabilities(["tls"]);
    expect(caps[0].authSupport).toBe("none");
  });

  it("returns none for sca", () => {
    const caps = getToolAuthCapabilities(["sca"]);
    expect(caps[0].authSupport).toBe("none");
  });

  it("handles multiple tools", () => {
    const caps = getToolAuthCapabilities(["headers", "nikto", "zap", "tls"]);
    expect(caps).toHaveLength(4);
    expect(caps[0].authSupport).toBe("full");
    expect(caps[1].authSupport).toBe("limited");
    expect(caps[2].authSupport).toBe("full");
    expect(caps[3].authSupport).toBe("none");
  });

  it("handles unknown tool", () => {
    const caps = getToolAuthCapabilities(["unknown"]);
    expect(caps[0].authSupport).toBe("none");
  });
});

// ─── ScanAuthMeta type ───────────────────────────────────────────────────────

describe("ScanAuthMeta type", () => {
  it("accepts minimal authenticated metadata", () => {
    const meta: ScanAuthMeta = { authMode: "authenticated" };
    expect(meta.authMode).toBe("authenticated");
    expect(meta.authMethod).toBeUndefined();
  });

  it("accepts full authenticated metadata", () => {
    const meta: ScanAuthMeta = {
      authMode: "authenticated",
      authMethod: "bearer-token",
      authRole: "admin",
      loginUrl: "https://example.com/login",
      authenticatedEndpointsTested: 15,
      totalEndpointsTested: 20,
    };
    expect(meta.authMode).toBe("authenticated");
    expect(meta.authMethod).toBe("bearer-token");
    expect(meta.authenticatedEndpointsTested).toBe(15);
  });
});

// ─── getToolAuthCapabilities — new PEN-* tools ────────────────────────────

describe("getToolAuthCapabilities — PEN-derived tools", () => {
  it("returns full support for ai-prompt", () => {
    const caps = getToolAuthCapabilities(["ai-prompt"]);
    expect(caps[0].authSupport).toBe("full");
    expect(caps[0].tool).toBe("ai-prompt");
  });

  it("returns full support for secret-leak", () => {
    const caps = getToolAuthCapabilities(["secret-leak"]);
    expect(caps[0].authSupport).toBe("full");
  });

  it("returns full support for url-norm", () => {
    const caps = getToolAuthCapabilities(["url-norm"]);
    expect(caps[0].authSupport).toBe("full");
  });

  it("returns full support for http-client", () => {
    const caps = getToolAuthCapabilities(["http-client"]);
    expect(caps[0].authSupport).toBe("full");
  });
});

// ─── testURLNormalisationBypass ───────────────────────────────────────────

vi.mock("./db", () => ({
  appendScanLog: vi.fn().mockResolvedValue(undefined),
  createFindings: vi.fn().mockResolvedValue(undefined),
  updateScan: vi.fn().mockResolvedValue(undefined),
  updateTarget: vi.fn().mockResolvedValue(undefined),
  getPreviousCompletedScan: vi.fn().mockResolvedValue(null),
  getFindingsByScan: vi.fn().mockResolvedValue([]),
}));

describe("testURLNormalisationBypass", () => {
  it("returns empty findings when target is unreachable", async () => {
    const findings = await testURLNormalisationBypass(999, "http://127.0.0.1:1");
    expect(findings).toEqual([]);
  });
});
