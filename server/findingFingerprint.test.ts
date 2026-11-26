import { describe, expect, it } from "vitest";
import { findingFingerprint } from "./findingFingerprint";

describe("findingFingerprint", () => {
  it("normalizes title/category/cwe", () => {
    expect(
      findingFingerprint({ title: " Missing CSP ", category: "Security Headers", cweId: "cwe-693" })
    ).toBe("security headers::missing csp::CWE-693");
  });
});
