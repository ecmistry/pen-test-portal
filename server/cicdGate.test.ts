import { describe, expect, it } from "vitest";

/** Mirror fail-on threshold logic used by cicd status payloads */
function shouldFail(
  counts: { critical: number; high: number; medium: number; low: number },
  failOn: "critical" | "high" | "medium" | "low"
): boolean {
  const order = ["critical", "high", "medium", "low"] as const;
  const idx = order.indexOf(failOn);
  return order.slice(0, idx + 1).some((k) => counts[k] > 0);
}

describe("CI fail-on-new filter", () => {
  it("keeps only titles in newItems", () => {
    const findings = [
      { title: "Old XSS", severity: "high" },
      { title: "Brand New SSRF", severity: "high" },
    ];
    const newItems = new Set(["brand new ssrf"]);
    const filtered = findings.filter((f) => newItems.has(f.title.toLowerCase()));
    expect(filtered).toHaveLength(1);
    expect(filtered[0].title).toBe("Brand New SSRF");
  });
});

describe("CI failOnSeverity gate", () => {
  it("fails on high when high present", () => {
    expect(shouldFail({ critical: 0, high: 1, medium: 0, low: 0 }, "high")).toBe(true);
  });

  it("passes when only medium and threshold is high", () => {
    expect(shouldFail({ critical: 0, high: 0, medium: 2, low: 0 }, "high")).toBe(false);
  });

  it("fails on critical threshold only for critical", () => {
    expect(shouldFail({ critical: 0, high: 5, medium: 0, low: 0 }, "critical")).toBe(false);
    expect(shouldFail({ critical: 1, high: 0, medium: 0, low: 0 }, "critical")).toBe(true);
  });
});

describe("retest match heuristics", () => {
  function stillPresent(
    findings: Array<{ title: string; cweId?: string | null; category: string; severity: string }>,
    parent: { title: string; cweId?: string | null; category: string; severity: string }
  ) {
    return findings.some((f) => {
      const sameTitle = f.title.toLowerCase() === parent.title.toLowerCase();
      const sameCwe = !!(parent.cweId && f.cweId && f.cweId === parent.cweId);
      const sameCat =
        f.category.toLowerCase() === parent.category.toLowerCase() &&
        f.severity === parent.severity;
      return sameTitle || sameCwe || sameCat;
    });
  }

  it("marks resolved when title gone", () => {
    expect(
      stillPresent(
        [{ title: "Other", category: "XSS", severity: "high" }],
        { title: "Reflected XSS", category: "XSS", severity: "high", cweId: "CWE-79" }
      )
    ).toBe(true); // same category+severity still matches
    expect(
      stillPresent(
        [{ title: "Other", category: "Headers", severity: "low" }],
        { title: "Reflected XSS", category: "XSS", severity: "high", cweId: "CWE-79" }
      )
    ).toBe(false);
  });

  it("matches by CWE", () => {
    expect(
      stillPresent(
        [{ title: "Different title", category: "Injection", severity: "medium", cweId: "CWE-79" }],
        { title: "Reflected XSS", category: "XSS", severity: "high", cweId: "CWE-79" }
      )
    ).toBe(true);
  });
});
