import { describe, expect, it } from "vitest";
import { assertCicdCanAccessScan } from "./routers";

describe("assertCicdCanAccessScan", () => {
  it("allows org-bound key for same-org scan", () => {
    expect(() =>
      assertCicdCanAccessScan({ userId: 5, orgId: 9 }, { userId: 1, orgId: 9 })
    ).not.toThrow();
  });

  it("forbids org-bound key for other-org scan", () => {
    expect(() =>
      assertCicdCanAccessScan({ userId: 5, orgId: 9 }, { userId: 1, orgId: 2 })
    ).toThrow(/organization/i);
  });

  it("allows user-bound key for own scan", () => {
    expect(() =>
      assertCicdCanAccessScan({ userId: 7, orgId: null }, { userId: 7, orgId: null })
    ).not.toThrow();
  });

  it("forbids user-bound key for another user's scan", () => {
    expect(() =>
      assertCicdCanAccessScan({ userId: 7, orgId: null }, { userId: 8, orgId: null })
    ).toThrow(/denied/i);
  });

  it("allows legacy env key only for system-owned scans (userId 0)", () => {
    expect(() =>
      assertCicdCanAccessScan({ userId: 0, orgId: null }, { userId: 0, orgId: null })
    ).not.toThrow();
  });

  it("blocks legacy env key from reading user-owned scans (IDOR)", () => {
    expect(() =>
      assertCicdCanAccessScan({ userId: 0, orgId: null }, { userId: 42, orgId: 3 })
    ).toThrow(/Legacy CICD_API_KEY/i);
  });
});
