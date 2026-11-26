import { describe, expect, it } from "vitest";
import { findingFingerprint, legacyFindingFingerprint, isWaivedFinding } from "./findingFingerprint";

describe("findingFingerprint", () => {
  it("normalizes title/category/cwe", () => {
    expect(
      findingFingerprint({ title: " Missing CSP ", category: "Security Headers", cweId: "cwe-693" })
    ).toBe("security headers::missing csp::CWE-693");
  });

  it("includes url when present", () => {
    const fp = findingFingerprint({
      title: "SQLi",
      category: "SQL Injection",
      cweId: "CWE-89",
      affectedUrl: "https://t.example/api/users/5?x=1",
    });
    expect(fp).toContain("CWE-89");
    expect(fp).toContain("/{id}");
  });

  it("matches legacy waivers via isWaivedFinding", () => {
    const set = new Set([legacyFindingFingerprint({ title: "Missing CSP", category: "Security Headers", cweId: "CWE-693" })]);
    expect(isWaivedFinding({ title: "Missing CSP", category: "Security Headers", cweId: "CWE-693", affectedUrl: "https://t/" }, set)).toBe(true);
  });
});
