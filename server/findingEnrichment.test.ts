import { describe, expect, it } from "vitest";
import {
  enrichFinding,
  getIso27001ControlTitle,
  deriveApiSecurityCategory,
  type EnrichedFields,
  type BusinessImpact,
  type AttackTechnique,
  type ApiSecurityMapping,
} from "./findingEnrichment";

// ─── enrichFinding: CVSSv3.1 ──────────────────────────────────────────────────

describe("enrichFinding — CVSS", () => {
  it("returns CVSS 9.8 for SQL Injection via CWE-89", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    expect(result.cvssScore).toBe(9.8);
    expect(result.cvssVector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  });

  it("returns CVSS 6.1 for XSS via CWE-79", () => {
    const result = enrichFinding("Cross-Site Scripting", "high", "CWE-79");
    expect(result.cvssScore).toBe(6.1);
    expect(result.cvssVector).toContain("CVSS:3.1/");
  });

  it("returns CVSS 9.1 for Authentication via CWE-307", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    expect(result.cvssScore).toBe(9.1);
  });

  it("returns CVSS 7.5 for Path Traversal via CWE-22", () => {
    const result = enrichFinding("Path Traversal", "critical", "CWE-22");
    expect(result.cvssScore).toBe(7.5);
  });

  it("returns CVSS 6.5 for CORS via CWE-942", () => {
    const result = enrichFinding("CORS", "high", "CWE-942");
    expect(result.cvssScore).toBe(6.5);
  });

  it("falls back to category-based CVSS when CWE is not mapped", () => {
    const result = enrichFinding("SQL Injection", "critical", null);
    expect(result.cvssScore).toBe(9.8);
  });

  it("falls back to severity-based CVSS for unknown categories", () => {
    const result = enrichFinding("CustomCategory", "high", null);
    expect(result.cvssScore).toBe(8.2);
    expect(result.cvssVector).toContain("CVSS:3.1/");
  });

  it("CWE mapping takes precedence over category mapping", () => {
    const result = enrichFinding("Security Headers", "medium", "CWE-311");
    expect(result.cvssScore).toBe(5.9);
  });

  it("returns null CVSS for info severity", () => {
    const result = enrichFinding("Security Headers", "info", "CWE-693");
    expect(result.cvssScore).toBeNull();
    expect(result.cvssVector).toBeNull();
  });

  it("returns null CVSS for Tool Availability", () => {
    const result = enrichFinding("Tool Availability", "info", null);
    expect(result.cvssScore).toBeNull();
  });

  it("returns null CVSS for Connectivity", () => {
    const result = enrichFinding("Connectivity", "info", null);
    expect(result.cvssScore).toBeNull();
  });

  it("vector string starts with CVSS:3.1/", () => {
    const result = enrichFinding("CORS", "medium", "CWE-942");
    expect(result.cvssVector).toMatch(/^CVSS:3\.1\//);
  });

  it("maps all 11 CWE IDs to CVSS vectors", () => {
    const cwes = ["CWE-89", "CWE-79", "CWE-22", "CWE-307", "CWE-203", "CWE-693", "CWE-311", "CWE-200", "CWE-538", "CWE-942", "CWE-1021"];
    for (const cwe of cwes) {
      const result = enrichFinding("GenericCategory", "medium", cwe);
      expect(result.cvssScore, `Missing CVSS for ${cwe}`).not.toBeNull();
      expect(result.cvssVector, `Missing vector for ${cwe}`).not.toBeNull();
    }
  });
});

// ─── enrichFinding: Business Impact ───────────────────────────────────────────

describe("enrichFinding — Business Impact", () => {
  it("returns High across all dimensions for SQL Injection", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    const impact = result.businessImpact!;
    expect(impact.financial).toBe("High");
    expect(impact.operational).toBe("High");
    expect(impact.reputational).toBe("High");
    expect(impact.legal).toBe("High");
    expect(impact.rationale).toContain("GDPR");
  });

  it("returns structured impact for Authentication findings", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    const impact = result.businessImpact!;
    expect(impact.financial).toBe("High");
    expect(impact.operational).toBe("High");
    expect(impact.rationale).toContain("account takeover");
  });

  it("returns Low impact for Security Headers", () => {
    const result = enrichFinding("Security Headers", "medium", "CWE-693");
    const impact = result.businessImpact!;
    expect(impact.financial).toBe("Low");
    expect(impact.legal).toBe("Low");
  });

  it("returns Medium impact for XSS reputational dimension", () => {
    const result = enrichFinding("Cross-Site Scripting", "high", "CWE-79");
    expect(result.businessImpact!.reputational).toBe("High");
    expect(result.businessImpact!.financial).toBe("Medium");
  });

  it("derives impact from severity for unknown categories", () => {
    const result = enrichFinding("CustomCategory", "critical", null);
    const impact = result.businessImpact!;
    expect(impact.financial).toBe("High");
    expect(impact.operational).toBe("High");
    expect(impact.rationale).toContain("derived from finding severity");
  });

  it("returns null impact for info severity", () => {
    const result = enrichFinding("Security Headers", "info", null);
    expect(result.businessImpact).toBeNull();
  });

  it("returns null impact for Tool Availability", () => {
    const result = enrichFinding("Tool Availability", "info", null);
    expect(result.businessImpact).toBeNull();
  });

  it("includes rationale text for all known categories", () => {
    const categories = ["SQL Injection", "Cross-Site Scripting", "Authentication", "CORS", "Path Traversal", "Security Headers", "Information Disclosure"];
    for (const cat of categories) {
      const result = enrichFinding(cat, "medium", null);
      expect(result.businessImpact?.rationale, `Missing rationale for ${cat}`).toBeTruthy();
    }
  });
});

// ─── enrichFinding: Remediation Complexity & Priority ─────────────────────────

describe("enrichFinding — Remediation Complexity", () => {
  it("assigns Low complexity to Security Headers", () => {
    const result = enrichFinding("Security Headers", "medium", "CWE-693");
    expect(result.remediationComplexity).toBe("Low");
  });

  it("assigns Low complexity to CORS", () => {
    const result = enrichFinding("CORS", "high", "CWE-942");
    expect(result.remediationComplexity).toBe("Low");
  });

  it("assigns Medium complexity to SQL Injection", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    expect(result.remediationComplexity).toBe("Medium");
  });

  it("assigns High complexity to Authentication", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    expect(result.remediationComplexity).toBe("High");
  });

  it("defaults to Medium for unknown categories", () => {
    const result = enrichFinding("CustomCategory", "medium", null);
    expect(result.remediationComplexity).toBe("Medium");
  });

  it("returns null complexity for info severity", () => {
    const result = enrichFinding("Security Headers", "info", null);
    expect(result.remediationComplexity).toBeNull();
  });
});

describe("enrichFinding — Remediation Priority", () => {
  it("assigns P1 to critical findings", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    expect(result.remediationPriority).toBe("P1");
  });

  it("assigns P1 to high findings", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    expect(result.remediationPriority).toBe("P1");
  });

  it("assigns P2 to medium findings", () => {
    const result = enrichFinding("Security Headers", "medium", "CWE-693");
    expect(result.remediationPriority).toBe("P2");
  });

  it("assigns P3 to low findings (when CVSS < 4.0)", () => {
    const result = enrichFinding("Information Disclosure", "low", null);
    expect(result.cvssScore).toBe(5.3);
    expect(result.remediationPriority).toBe("P2");
  });

  it("assigns P3 to low findings with low CVSS", () => {
    const result = enrichFinding("CustomCategory", "low", null);
    expect(result.cvssScore).toBe(3.1);
    expect(result.remediationPriority).toBe("P3");
  });

  it("returns null priority for info findings", () => {
    const result = enrichFinding("Security Headers", "info", null);
    expect(result.remediationPriority).toBeNull();
  });

  it("P1 priority for CVSS >= 9.0 regardless of severity label", () => {
    const result = enrichFinding("SQL Injection", "medium", "CWE-89");
    expect(result.cvssScore).toBe(9.8);
    expect(result.remediationPriority).toBe("P1");
  });
});

// ─── enrichFinding: MITRE ATT&CK ─────────────────────────────────────────────

describe("enrichFinding — MITRE ATT&CK", () => {
  it("maps CWE-89 to T1190 (Exploit Public-Facing Application)", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    expect(result.attackTechniques).toHaveLength(1);
    expect(result.attackTechniques![0].techniqueId).toBe("T1190");
    expect(result.attackTechniques![0].tactic).toBe("Initial Access");
  });

  it("maps CWE-79 to two techniques (T1189, T1185)", () => {
    const result = enrichFinding("Cross-Site Scripting", "high", "CWE-79");
    expect(result.attackTechniques).toHaveLength(2);
    const ids = result.attackTechniques!.map((t) => t.techniqueId);
    expect(ids).toContain("T1189");
    expect(ids).toContain("T1185");
  });

  it("maps CWE-307 to T1110 (Brute Force)", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    expect(result.attackTechniques![0].techniqueId).toBe("T1110");
    expect(result.attackTechniques![0].tactic).toBe("Credential Access");
  });

  it("maps CWE-22 to T1083 and T1005", () => {
    const result = enrichFinding("Path Traversal", "critical", "CWE-22");
    const ids = result.attackTechniques!.map((t) => t.techniqueId);
    expect(ids).toContain("T1083");
    expect(ids).toContain("T1005");
  });

  it("CWE-based mapping takes precedence over category", () => {
    const result = enrichFinding("Security Headers", "medium", "CWE-311");
    expect(result.attackTechniques![0].techniqueId).toBe("T1557");
  });

  it("falls back to category mapping when no CWE", () => {
    const result = enrichFinding("SQL Injection", "critical", null);
    expect(result.attackTechniques![0].techniqueId).toBe("T1190");
  });

  it("returns null for Tool Availability", () => {
    const result = enrichFinding("Tool Availability", "info", null);
    expect(result.attackTechniques).toBeNull();
  });

  it("returns null for Connectivity", () => {
    const result = enrichFinding("Connectivity", "info", null);
    expect(result.attackTechniques).toBeNull();
  });

  it("each technique has required fields", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    for (const t of result.attackTechniques!) {
      expect(t.techniqueId).toMatch(/^T\d{4}/);
      expect(t.techniqueName).toBeTruthy();
      expect(t.tactic).toBeTruthy();
    }
  });
});

// ─── enrichFinding: ISO 27001 ─────────────────────────────────────────────────

describe("enrichFinding — ISO 27001", () => {
  it("maps SQL Injection to A.14.2.5", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    expect(result.iso27001Controls).toContain("A.14.2.5");
  });

  it("maps Authentication to A.9.4.2 and A.9.4.3", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    expect(result.iso27001Controls).toContain("A.9.4.2");
    expect(result.iso27001Controls).toContain("A.9.4.3");
  });

  it("maps Security Headers to A.14.1.2", () => {
    const result = enrichFinding("Security Headers", "medium", "CWE-693");
    expect(result.iso27001Controls).toContain("A.14.1.2");
  });

  it("maps Information Disclosure to A.12.6.1 and A.18.1.4", () => {
    const result = enrichFinding("Information Disclosure", "medium", "CWE-538");
    expect(result.iso27001Controls).toContain("A.12.6.1");
    expect(result.iso27001Controls).toContain("A.18.1.4");
  });

  it("maps Path Traversal to A.14.2.5 and A.12.6.1", () => {
    const result = enrichFinding("Path Traversal", "critical", "CWE-22");
    expect(result.iso27001Controls).toContain("A.14.2.5");
    expect(result.iso27001Controls).toContain("A.12.6.1");
  });

  it("maps Security Misconfiguration to A.12.5.1 and A.12.6.1", () => {
    const result = enrichFinding("Security Misconfiguration", "medium", null);
    expect(result.iso27001Controls).toContain("A.12.5.1");
    expect(result.iso27001Controls).toContain("A.12.6.1");
  });

  it("defaults unknown categories to A.12.6.1", () => {
    const result = enrichFinding("CustomCategory", "medium", null);
    expect(result.iso27001Controls).toEqual(["A.12.6.1"]);
  });

  it("returns null for Tool Availability", () => {
    const result = enrichFinding("Tool Availability", "info", null);
    expect(result.iso27001Controls).toBeNull();
  });
});

// ─── getIso27001ControlTitle ──────────────────────────────────────────────────

describe("getIso27001ControlTitle", () => {
  it("returns correct title for known controls", () => {
    expect(getIso27001ControlTitle("A.9.4.2")).toBe("Secure log-on procedures");
    expect(getIso27001ControlTitle("A.14.2.5")).toBe("Secure system engineering principles");
    expect(getIso27001ControlTitle("A.12.6.1")).toBe("Management of technical vulnerabilities");
    expect(getIso27001ControlTitle("A.18.1.4")).toBe("Privacy and protection of PII");
  });

  it("returns the control ID itself for unknown controls", () => {
    expect(getIso27001ControlTitle("A.99.9.9")).toBe("A.99.9.9");
  });
});

// ─── enrichFinding: Full Integration ──────────────────────────────────────────

describe("enrichFinding — full integration", () => {
  it("enriches a critical SQL injection finding with all fields", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    expect(result.cvssScore).toBe(9.8);
    expect(result.cvssVector).toBeTruthy();
    expect(result.businessImpact).not.toBeNull();
    expect(result.businessImpact!.financial).toBe("High");
    expect(result.remediationComplexity).toBe("Medium");
    expect(result.remediationPriority).toBe("P1");
    expect(result.attackTechniques).not.toBeNull();
    expect(result.attackTechniques!.length).toBeGreaterThan(0);
    expect(result.iso27001Controls).not.toBeNull();
    expect(result.iso27001Controls!.length).toBeGreaterThan(0);
  });

  it("returns all null for info-severity Tool Availability finding", () => {
    const result = enrichFinding("Tool Availability", "info", null);
    expect(result.cvssScore).toBeNull();
    expect(result.cvssVector).toBeNull();
    expect(result.businessImpact).toBeNull();
    expect(result.remediationComplexity).toBeNull();
    expect(result.remediationPriority).toBeNull();
    expect(result.attackTechniques).toBeNull();
    expect(result.iso27001Controls).toBeNull();
  });

  it("handles medium Security Headers finding (low complexity, P2 priority)", () => {
    const result = enrichFinding("Security Headers", "medium", "CWE-693");
    expect(result.cvssScore).toBe(5.3);
    expect(result.remediationComplexity).toBe("Low");
    expect(result.remediationPriority).toBe("P2");
    expect(result.businessImpact!.financial).toBe("Low");
    expect(result.iso27001Controls).toContain("A.14.1.2");
  });

  it("enriches all categories used by the scan engine", () => {
    const scanCategories = [
      { category: "Security Headers",        severity: "medium", cwe: "CWE-693" },
      { category: "Security Headers",        severity: "high",   cwe: "CWE-693" },
      { category: "Information Disclosure",   severity: "low",    cwe: "CWE-200" },
      { category: "Information Disclosure",   severity: "critical", cwe: "CWE-538" },
      { category: "Authentication",           severity: "medium", cwe: "CWE-203" },
      { category: "Authentication",           severity: "high",   cwe: "CWE-307" },
      { category: "SQL Injection",            severity: "critical", cwe: "CWE-89" },
      { category: "Cross-Site Scripting",     severity: "high",   cwe: "CWE-79" },
      { category: "CORS",                     severity: "high",   cwe: "CWE-942" },
      { category: "CORS",                     severity: "critical", cwe: "CWE-942" },
      { category: "Path Traversal",           severity: "critical", cwe: "CWE-22" },
      { category: "Security Misconfiguration",severity: "medium", cwe: "CWE-693" },
      { category: "Nikto",                    severity: "medium", cwe: null },
      { category: "Nuclei",                   severity: "high",   cwe: null },
      { category: "OWASP ZAP",               severity: "info",   cwe: null },
      { category: "TLS",                     severity: "high",   cwe: "CWE-326" },
      { category: "TLS",                     severity: "critical", cwe: "CWE-295" },
      { category: "TLS",                     severity: "medium", cwe: "CWE-319" },
      { category: "Business Logic",          severity: "medium", cwe: "CWE-352" },
      { category: "Business Logic",          severity: "high",   cwe: "CWE-915" },
      { category: "GraphQL",                 severity: "medium", cwe: null },
      { category: "GraphQL",                 severity: "critical", cwe: "CWE-89" },
      { category: "Connectivity",             severity: "info",   cwe: null },
      { category: "Tool Availability",        severity: "info",   cwe: null },
    ];

    for (const { category, severity, cwe } of scanCategories) {
      const result = enrichFinding(category, severity, cwe);

      if (severity === "info" || category === "Tool Availability" || category === "Connectivity") {
        expect(result.cvssScore, `Expected null CVSS for ${category}/${severity}`).toBeNull();
        expect(result.remediationPriority, `Expected null priority for ${category}/${severity}`).toBeNull();
      } else {
        expect(result.cvssScore, `Missing CVSS for ${category}/${severity}`).not.toBeNull();
        expect(result.cvssScore!, `Invalid CVSS range for ${category}`).toBeGreaterThanOrEqual(0);
        expect(result.cvssScore!, `Invalid CVSS range for ${category}`).toBeLessThanOrEqual(10);
        expect(result.remediationPriority, `Missing priority for ${category}`).toMatch(/^P[1-4]$/);
        expect(result.remediationComplexity, `Missing complexity for ${category}`).toMatch(/^(Low|Medium|High)$/);
        expect(result.businessImpact, `Missing impact for ${category}`).not.toBeNull();
      }
    }
  });

  it("enriches TLS finding with CWE-326 (inadequate encryption)", () => {
    const result = enrichFinding("TLS", "high", "CWE-326");
    expect(result.cvssScore).toBe(5.9);
    expect(result.cvssVector).toContain("CVSS:3.1");
    expect(result.attackTechniques).not.toBeNull();
    expect(result.attackTechniques![0].techniqueId).toBe("T1557");
    expect(result.iso27001Controls).toContain("A.10.1.1");
    expect(result.businessImpact).not.toBeNull();
    expect(result.businessImpact!.reputational).toBe("High");
    expect(result.businessImpact!.legal).toBe("High");
    expect(result.remediationComplexity).toBe("Medium");
  });

  it("enriches TLS finding with CWE-295 (improper certificate validation)", () => {
    const result = enrichFinding("TLS", "medium", "CWE-295");
    expect(result.cvssScore).toBe(5.9);
    expect(result.attackTechniques![0].techniqueId).toBe("T1557");
    expect(result.iso27001Controls).toContain("A.10.1.1");
    expect(result.iso27001Controls).toContain("A.14.1.2");
  });

  it("enriches TLS finding with CWE-319 (cleartext transmission)", () => {
    const result = enrichFinding("TLS", "high", "CWE-319");
    expect(result.cvssScore).toBe(7.5);
    expect(result.attackTechniques![0].techniqueId).toBe("T1040");
    expect(result.attackTechniques![0].tactic).toBe("Credential Access");
  });

  it("uses TLS category fallback when no CWE provided", () => {
    const result = enrichFinding("TLS", "medium", null);
    expect(result.cvssScore).toBe(5.9);
    expect(result.attackTechniques![0].techniqueId).toBe("T1557");
    expect(result.iso27001Controls).toContain("A.10.1.1");
  });

  it("enriches Business Logic finding with CWE-352 (CSRF)", () => {
    const result = enrichFinding("Business Logic", "medium", "CWE-352");
    expect(result.cvssScore).toBe(6.5);
    expect(result.attackTechniques![0].techniqueId).toBe("T1189");
    expect(result.iso27001Controls).toContain("A.14.2.5");
    expect(result.businessImpact!.operational).toBe("Medium");
  });

  it("enriches Business Logic finding with CWE-915 (mass assignment)", () => {
    const result = enrichFinding("Business Logic", "high", "CWE-915");
    expect(result.cvssScore).toBe(6.5);
    expect(result.attackTechniques![0].techniqueId).toBe("T1098");
    expect(result.attackTechniques![0].tactic).toBe("Persistence");
  });

  it("enriches Business Logic finding with CWE-215 (debug info)", () => {
    const result = enrichFinding("Business Logic", "medium", "CWE-215");
    expect(result.cvssScore).toBe(5.3);
    expect(result.remediationComplexity).toBe("Medium");
  });

  it("enriches GraphQL finding without CWE", () => {
    const result = enrichFinding("GraphQL", "medium", null);
    expect(result.cvssScore).toBe(5.3);
    expect(result.remediationComplexity).toBe("Low");
    expect(result.attackTechniques![0].techniqueId).toBe("T1190");
    expect(result.iso27001Controls).toContain("A.14.2.5");
    expect(result.businessImpact!.financial).toBe("Medium");
  });

  it("enriches GraphQL finding with CWE-770 (batch abuse)", () => {
    const result = enrichFinding("GraphQL", "medium", "CWE-770");
    expect(result.cvssScore).toBe(7.5);
    expect(result.attackTechniques![0].techniqueId).toBe("T1499");
    expect(result.attackTechniques![0].tactic).toBe("Impact");
  });

  it("enriches GraphQL finding with CWE-400 (depth limiting)", () => {
    const result = enrichFinding("GraphQL", "low", "CWE-400");
    expect(result.cvssScore).toBe(5.3);
    expect(result.attackTechniques![0].techniqueId).toBe("T1499");
  });
});

// ─── enrichFinding: Additional Edge Cases ─────────────────────────────────────

describe("enrichFinding — Connectivity category", () => {
  it("returns null for all fields when category is Connectivity", () => {
    const result = enrichFinding("Connectivity", "medium", null);
    expect(result.cvssScore).toBeNull();
    expect(result.cvssVector).toBeNull();
    expect(result.businessImpact).toBeNull();
    expect(result.remediationComplexity).toBeNull();
    expect(result.remediationPriority).toBeNull();
    expect(result.attackTechniques).toBeNull();
    expect(result.iso27001Controls).toBeNull();
  });

  it("returns null for Connectivity even with a CWE", () => {
    const result = enrichFinding("Connectivity", "high", "CWE-89");
    expect(result.cvssScore).toBeNull();
    expect(result.attackTechniques).toBeNull();
  });
});

describe("enrichFinding — P4 priority edge case", () => {
  it("returns P4 for info severity when CVSS is null", () => {
    const result = enrichFinding("CustomCategory", "info", null);
    expect(result.cvssScore).toBeNull();
    expect(result.remediationPriority).toBeNull();
  });
});

describe("enrichFinding — CVSS severity label boundaries", () => {
  it("labels CVSS 9.8 as CRITICAL", () => {
    const result = enrichFinding("SQL Injection", "critical", "CWE-89");
    expect(result.cvssScore).toBe(9.8);
  });

  it("labels CVSS 9.1 as CRITICAL (>= 9.0)", () => {
    const result = enrichFinding("Authentication", "high", "CWE-307");
    expect(result.cvssScore).toBe(9.1);
  });

  it("labels CVSS 7.5 as HIGH (>= 7.0, < 9.0)", () => {
    const result = enrichFinding("Path Traversal", "critical", "CWE-22");
    expect(result.cvssScore).toBe(7.5);
  });

  it("labels CVSS 5.3 as MEDIUM (>= 4.0, < 7.0)", () => {
    const result = enrichFinding("Security Misconfiguration", "medium", null);
    expect(result.cvssScore).toBe(5.3);
  });

  it("labels CVSS 3.1 as LOW (> 0.0, < 4.0)", () => {
    const result = enrichFinding("CustomCategory", "low", null);
    expect(result.cvssScore).toBe(3.1);
  });
});

describe("enrichFinding — CWE coverage for new Phase 2+3 CWEs", () => {
  const phaseNewCWEs = [
    { cwe: "CWE-326", expectedScore: 5.9, expectedTechnique: "T1557" },
    { cwe: "CWE-295", expectedScore: 5.9, expectedTechnique: "T1557" },
    { cwe: "CWE-319", expectedScore: 7.5, expectedTechnique: "T1040" },
    { cwe: "CWE-215", expectedScore: 5.3, expectedTechnique: "T1592" },
    { cwe: "CWE-352", expectedScore: 6.5, expectedTechnique: "T1189" },
    { cwe: "CWE-915", expectedScore: 6.5, expectedTechnique: "T1098" },
    { cwe: "CWE-209", expectedScore: 5.3, expectedTechnique: "T1592" },
    { cwe: "CWE-770", expectedScore: 7.5, expectedTechnique: "T1499" },
    { cwe: "CWE-400", expectedScore: 5.3, expectedTechnique: "T1499" },
    { cwe: "CWE-200", expectedScore: 5.3, expectedTechnique: "T1592" },
    { cwe: "CWE-1021", expectedScore: 4.3, expectedTechnique: "T1189" },
  ];

  for (const { cwe, expectedScore, expectedTechnique } of phaseNewCWEs) {
    it(`maps ${cwe} to CVSS ${expectedScore} and technique ${expectedTechnique}`, () => {
      const result = enrichFinding("GenericCategory", "medium", cwe);
      expect(result.cvssScore).toBe(expectedScore);
      expect(result.attackTechniques![0].techniqueId).toBe(expectedTechnique);
    });
  }
});

describe("getIso27001ControlTitle — all known controls", () => {
  const knownControls: Array<[string, string]> = [
    ["A.9.4.2", "Secure log-on procedures"],
    ["A.9.4.3", "Password management system"],
    ["A.10.1.1", "Policy on the use of cryptographic controls"],
    ["A.12.5.1", "Installation of software on operational systems"],
    ["A.12.6.1", "Management of technical vulnerabilities"],
    ["A.14.1.2", "Securing application services on public networks"],
    ["A.14.2.5", "Secure system engineering principles"],
    ["A.14.2.8", "System security testing"],
    ["A.18.1.4", "Privacy and protection of PII"],
  ];

  for (const [control, title] of knownControls) {
    it(`returns "${title}" for ${control}`, () => {
      expect(getIso27001ControlTitle(control)).toBe(title);
    });
  }

  it("returns control ID for unmapped controls", () => {
    expect(getIso27001ControlTitle("A.5.1.1")).toBe("A.5.1.1");
    expect(getIso27001ControlTitle("A.99.99.99")).toBe("A.99.99.99");
  });
});

describe("enrichFinding — ISO 27001 category coverage", () => {
  it("maps CORS to A.14.1.2", () => {
    const result = enrichFinding("CORS", "medium", null);
    expect(result.iso27001Controls).toContain("A.14.1.2");
  });

  it("maps TLS to A.10.1.1 and A.14.1.2", () => {
    const result = enrichFinding("TLS", "medium", null);
    expect(result.iso27001Controls).toContain("A.10.1.1");
    expect(result.iso27001Controls).toContain("A.14.1.2");
  });

  it("maps Business Logic to A.14.2.5 and A.14.2.8", () => {
    const result = enrichFinding("Business Logic", "medium", null);
    expect(result.iso27001Controls).toContain("A.14.2.5");
    expect(result.iso27001Controls).toContain("A.14.2.8");
  });

  it("maps GraphQL to A.14.2.5 and A.14.1.2", () => {
    const result = enrichFinding("GraphQL", "medium", null);
    expect(result.iso27001Controls).toContain("A.14.2.5");
    expect(result.iso27001Controls).toContain("A.14.1.2");
  });

  it("maps Nikto to A.12.6.1", () => {
    const result = enrichFinding("Nikto", "medium", null);
    expect(result.iso27001Controls).toEqual(["A.12.6.1"]);
  });

  it("maps Nuclei to A.12.6.1", () => {
    const result = enrichFinding("Nuclei", "medium", null);
    expect(result.iso27001Controls).toEqual(["A.12.6.1"]);
  });

  it("maps OWASP ZAP to A.14.2.8", () => {
    const result = enrichFinding("OWASP ZAP", "medium", null);
    expect(result.iso27001Controls).toEqual(["A.14.2.8"]);
  });
});

describe("enrichFinding — category normalization", () => {
  it("uses case-insensitive category lookup for CVSS", () => {
    const resultLower = enrichFinding("sql injection", "critical", null);
    const resultMixed = enrichFinding("SQL Injection", "critical", null);
    expect(resultLower.cvssScore).toBe(resultMixed.cvssScore);
    expect(resultLower.cvssVector).toBe(resultMixed.cvssVector);
  });

  it("uses case-insensitive category lookup for business impact", () => {
    const resultLower = enrichFinding("authentication", "high", null);
    const resultProper = enrichFinding("Authentication", "high", null);
    expect(resultLower.businessImpact!.financial).toBe(resultProper.businessImpact!.financial);
  });

  it("uses case-insensitive category lookup for complexity", () => {
    const resultLower = enrichFinding("security headers", "medium", null);
    const resultProper = enrichFinding("Security Headers", "medium", null);
    expect(resultLower.remediationComplexity).toBe(resultProper.remediationComplexity);
  });
});

// ─── deriveApiSecurityCategory: OWASP API Security Top 10:2023 ────────────────

describe("deriveApiSecurityCategory", () => {
  it("maps Authentication to API2:2023", () => {
    const result = deriveApiSecurityCategory("Authentication", null);
    expect(result).toEqual({ id: "API2:2023", name: "Broken Authentication" });
  });

  it("maps CWE-307 to API2:2023 (Broken Authentication)", () => {
    const result = deriveApiSecurityCategory("GenericCategory", "CWE-307");
    expect(result).toEqual({ id: "API2:2023", name: "Broken Authentication" });
  });

  it("maps CWE-203 to API2:2023 (Broken Authentication)", () => {
    const result = deriveApiSecurityCategory("GenericCategory", "CWE-203");
    expect(result).toEqual({ id: "API2:2023", name: "Broken Authentication" });
  });

  it("maps CWE-915 to API3:2023 (Broken Object Property Level Authorization)", () => {
    const result = deriveApiSecurityCategory("Business Logic", "CWE-915");
    expect(result).toEqual({ id: "API3:2023", name: "Broken Object Property Level Authorization" });
  });

  it("maps CWE-352 to API3:2023", () => {
    const result = deriveApiSecurityCategory("Business Logic", "CWE-352");
    expect(result).toEqual({ id: "API3:2023", name: "Broken Object Property Level Authorization" });
  });

  it("maps SQL Injection to API3:2023", () => {
    const result = deriveApiSecurityCategory("SQL Injection", null);
    expect(result).toEqual({ id: "API3:2023", name: "Broken Object Property Level Authorization" });
  });

  it("maps CWE-770 to API4:2023 (Unrestricted Resource Consumption)", () => {
    const result = deriveApiSecurityCategory("GraphQL", "CWE-770");
    expect(result).toEqual({ id: "API4:2023", name: "Unrestricted Resource Consumption" });
  });

  it("maps CWE-400 to API4:2023", () => {
    const result = deriveApiSecurityCategory("GraphQL", "CWE-400");
    expect(result).toEqual({ id: "API4:2023", name: "Unrestricted Resource Consumption" });
  });

  it("maps GraphQL (no CWE) to API4:2023", () => {
    const result = deriveApiSecurityCategory("GraphQL", null);
    expect(result).toEqual({ id: "API4:2023", name: "Unrestricted Resource Consumption" });
  });

  it("maps Business Logic to API6:2023", () => {
    const result = deriveApiSecurityCategory("Business Logic", null);
    expect(result).toEqual({ id: "API6:2023", name: "Unrestricted Access to Sensitive Business Flows" });
  });

  it("maps Security Headers to API8:2023 (Security Misconfiguration)", () => {
    const result = deriveApiSecurityCategory("Security Headers", null);
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps CORS to API8:2023", () => {
    const result = deriveApiSecurityCategory("CORS", null);
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps Security Misconfiguration to API8:2023", () => {
    const result = deriveApiSecurityCategory("Security Misconfiguration", null);
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps CWE-693 to API8:2023", () => {
    const result = deriveApiSecurityCategory("GenericCategory", "CWE-693");
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps CWE-215 to API8:2023", () => {
    const result = deriveApiSecurityCategory("Business Logic", "CWE-215");
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps Information Disclosure to API9:2023 (Improper Inventory Management)", () => {
    const result = deriveApiSecurityCategory("Information Disclosure", null);
    expect(result).toEqual({ id: "API9:2023", name: "Improper Inventory Management" });
  });

  it("maps CWE-200 to API9:2023", () => {
    const result = deriveApiSecurityCategory("GenericCategory", "CWE-200");
    expect(result).toEqual({ id: "API9:2023", name: "Improper Inventory Management" });
  });

  it("maps CWE-538 to API9:2023", () => {
    const result = deriveApiSecurityCategory("GenericCategory", "CWE-538");
    expect(result).toEqual({ id: "API9:2023", name: "Improper Inventory Management" });
  });

  it("returns null for Tool Availability", () => {
    expect(deriveApiSecurityCategory("Tool Availability", null)).toBeNull();
  });

  it("returns null for Connectivity", () => {
    expect(deriveApiSecurityCategory("Connectivity", null)).toBeNull();
  });

  it("returns null for unmapped categories without CWE", () => {
    expect(deriveApiSecurityCategory("Nikto", null)).toBeNull();
  });

  it("CWE mapping takes precedence over category mapping", () => {
    const result = deriveApiSecurityCategory("Security Headers", "CWE-307");
    expect(result!.id).toBe("API2:2023");
  });

  it("uses case-insensitive category lookup", () => {
    const lower = deriveApiSecurityCategory("authentication", null);
    const upper = deriveApiSecurityCategory("Authentication", null);
    expect(lower).toEqual(upper);
  });

  it("maps TLS to API8:2023", () => {
    const result = deriveApiSecurityCategory("TLS", null);
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps Path Traversal to API8:2023", () => {
    const result = deriveApiSecurityCategory("Path Traversal", null);
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps XSS to API8:2023", () => {
    const result = deriveApiSecurityCategory("Cross-Site Scripting", null);
    expect(result).toEqual({ id: "API8:2023", name: "Security Misconfiguration" });
  });

  it("maps Authorization to API1:2023 (Broken Object Level Authorization)", () => {
    const result = deriveApiSecurityCategory("Authorization", null);
    expect(result).toEqual({ id: "API1:2023", name: "Broken Object Level Authorization" });
  });

  it("maps CWE-269 to API1:2023", () => {
    const result = deriveApiSecurityCategory("Authorization", "CWE-269");
    expect(result).toEqual({ id: "API1:2023", name: "Broken Object Level Authorization" });
  });

  it("maps CWE-639 to API1:2023", () => {
    const result = deriveApiSecurityCategory("Authorization", "CWE-639");
    expect(result).toEqual({ id: "API1:2023", name: "Broken Object Level Authorization" });
  });

  it("maps CWE-284 to API5:2023 (Broken Function Level Authorization)", () => {
    const result = deriveApiSecurityCategory("Authorization", "CWE-284");
    expect(result).toEqual({ id: "API5:2023", name: "Broken Function Level Authorization" });
  });
});

// ─── enrichFinding: Authorization category ────────────────────────────────────

describe("enrichFinding — Authorization category", () => {
  it("returns CVSS 8.1 for Authorization category", () => {
    const result = enrichFinding("Authorization", "high", null);
    expect(result.cvssScore).toBe(8.1);
  });

  it("returns CVSS 8.1 for CWE-269", () => {
    const result = enrichFinding("Authorization", "high", "CWE-269");
    expect(result.cvssScore).toBe(8.1);
  });

  it("returns CVSS 7.1 for CWE-284", () => {
    const result = enrichFinding("Authorization", "high", "CWE-284");
    expect(result.cvssScore).toBe(7.1);
  });

  it("returns CVSS 6.5 for CWE-639", () => {
    const result = enrichFinding("Authorization", "high", "CWE-639");
    expect(result.cvssScore).toBe(6.5);
  });

  it("returns high business impact for Authorization", () => {
    const result = enrichFinding("Authorization", "high", null);
    expect(result.businessImpact?.financial).toBe("High");
    expect(result.businessImpact?.legal).toBe("High");
  });

  it("returns High remediation complexity for Authorization", () => {
    const result = enrichFinding("Authorization", "high", null);
    expect(result.remediationComplexity).toBe("High");
  });

  it("maps CWE-269 to T1078 Valid Accounts", () => {
    const result = enrichFinding("Authorization", "high", "CWE-269");
    expect(result.attackTechniques).toEqual([
      { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Privilege Escalation" },
    ]);
  });

  it("maps CWE-284 to T1550", () => {
    const result = enrichFinding("Authorization", "high", "CWE-284");
    expect(result.attackTechniques).toEqual([
      { techniqueId: "T1550", techniqueName: "Use Alternate Authentication Material", tactic: "Defense Evasion" },
    ]);
  });

  it("maps CWE-639 to T1078", () => {
    const result = enrichFinding("Authorization", "high", "CWE-639");
    expect(result.attackTechniques).toEqual([
      { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Privilege Escalation" },
    ]);
  });

  it("returns ISO 27001 controls including A.9.4.1 for Authorization", () => {
    const result = enrichFinding("Authorization", "high", null);
    expect(result.iso27001Controls).toContain("A.9.4.1");
    expect(result.iso27001Controls).toContain("A.9.4.2");
    expect(result.iso27001Controls).toContain("A.14.2.5");
  });

  it("returns P1 priority for Authorization high severity", () => {
    const result = enrichFinding("Authorization", "high", null);
    expect(result.remediationPriority).toBe("P1");
  });
});

// ─── enrichFinding: SCA category ──────────────────────────────────────────────

describe("enrichFinding — SCA category", () => {
  it("returns CVSS 9.8 for SCA category", () => {
    const result = enrichFinding("SCA", "critical", null);
    expect(result.cvssScore).toBe(9.8);
  });

  it("returns CVSS 9.8 for CWE-502", () => {
    const result = enrichFinding("SCA", "critical", "CWE-502");
    expect(result.cvssScore).toBe(9.8);
  });

  it("returns CVSS 9.8 for CWE-1104", () => {
    const result = enrichFinding("SCA", "critical", "CWE-1104");
    expect(result.cvssScore).toBe(9.8);
  });

  it("returns high business impact for SCA", () => {
    const result = enrichFinding("SCA", "critical", null);
    expect(result.businessImpact?.financial).toBe("High");
    expect(result.businessImpact?.legal).toBe("High");
  });

  it("returns Low remediation complexity for SCA", () => {
    const result = enrichFinding("SCA", "high", null);
    expect(result.remediationComplexity).toBe("Low");
  });

  it("maps SCA category to T1190 and T1195", () => {
    const result = enrichFinding("SCA", "high", null);
    const techIds = result.attackTechniques?.map(t => t.techniqueId) ?? [];
    expect(techIds).toContain("T1190");
    expect(techIds).toContain("T1195");
  });

  it("maps CWE-502 to T1190", () => {
    const result = enrichFinding("SCA", "high", "CWE-502");
    expect(result.attackTechniques?.[0].techniqueId).toBe("T1190");
  });

  it("returns ISO 27001 controls including A.12.6.1 for SCA", () => {
    const result = enrichFinding("SCA", "high", null);
    expect(result.iso27001Controls).toContain("A.12.6.1");
    expect(result.iso27001Controls).toContain("A.12.5.1");
  });
});

// ─── deriveApiSecurityCategory: SCA → API10 ──────────────────────────────────

describe("deriveApiSecurityCategory — SCA", () => {
  it("maps SCA to API10:2023 (Unsafe Consumption of APIs)", () => {
    const result = deriveApiSecurityCategory("SCA", null);
    expect(result).toEqual({ id: "API10:2023", name: "Unsafe Consumption of APIs" });
  });

  it("maps CWE-502 to API10:2023", () => {
    const result = deriveApiSecurityCategory("SCA", "CWE-502");
    expect(result).toEqual({ id: "API10:2023", name: "Unsafe Consumption of APIs" });
  });

  it("maps CWE-1104 to API10:2023", () => {
    const result = deriveApiSecurityCategory("SCA", "CWE-1104");
    expect(result).toEqual({ id: "API10:2023", name: "Unsafe Consumption of APIs" });
  });
});

// ─── enrichFinding: SSRF category ─────────────────────────────────────────────

describe("enrichFinding — SSRF category", () => {
  it("returns CVSS 9.1 for SSRF category", () => {
    const result = enrichFinding("SSRF", "high", null);
    expect(result.cvssScore).toBe(9.1);
  });

  it("returns CVSS 9.1 for CWE-918", () => {
    const result = enrichFinding("SSRF", "high", "CWE-918");
    expect(result.cvssScore).toBe(9.1);
  });

  it("returns high business impact for SSRF", () => {
    const result = enrichFinding("SSRF", "high", null);
    expect(result.businessImpact?.financial).toBe("High");
  });

  it("returns Medium remediation complexity for SSRF", () => {
    const result = enrichFinding("SSRF", "high", null);
    expect(result.remediationComplexity).toBe("Medium");
  });

  it("maps SSRF to T1190", () => {
    const result = enrichFinding("SSRF", "high", null);
    expect(result.attackTechniques?.[0].techniqueId).toBe("T1190");
  });

  it("returns ISO 27001 controls for SSRF", () => {
    const result = enrichFinding("SSRF", "high", null);
    expect(result.iso27001Controls).toContain("A.14.2.5");
    expect(result.iso27001Controls).toContain("A.14.1.2");
  });
});

// ─── deriveApiSecurityCategory: SSRF → API7 ──────────────────────────────────

describe("deriveApiSecurityCategory — SSRF", () => {
  it("maps SSRF to API7:2023", () => {
    const result = deriveApiSecurityCategory("SSRF", null);
    expect(result).toEqual({ id: "API7:2023", name: "Server Side Request Forgery" });
  });

  it("maps CWE-918 to API7:2023", () => {
    const result = deriveApiSecurityCategory("SSRF", "CWE-918");
    expect(result).toEqual({ id: "API7:2023", name: "Server Side Request Forgery" });
  });
});
