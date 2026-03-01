import { describe, expect, it } from "vitest";
import {
  calculateScore,
  isSpaFallback,
  hasFileSpecificContent,
} from "./scanEngine";

describe("calculateScore", () => {
  it("returns 100 and info when no findings", () => {
    const { score, riskLevel } = calculateScore([]);
    expect(score).toBe(100);
    expect(riskLevel).toBe("info");
  });

  it("deducts for critical findings and caps count", () => {
    const criticals = Array.from({ length: 5 }, () => ({ severity: "critical" as const }));
    const { score, riskLevel } = calculateScore(criticals);
    expect(score).toBeLessThan(100);
    // Only first 2 criticals count (maxCount: 2), 2 * 22 = 44 → score 56 → risk "high" (40 <= score < 60)
    expect(score).toBe(56);
    expect(riskLevel).toBe("high");
  });

  it("deducts for high/medium/low and caps per severity", () => {
    const findings = [
      { severity: "high" as const },
      { severity: "high" as const },
      { severity: "medium" as const },
    ];
    const { score, riskLevel } = calculateScore(findings);
    expect(score).toBe(100 - 12 - 12 - 5); // 71
    expect(score).toBe(71);
    expect(["medium", "low", "info"]).toContain(riskLevel);
  });

  it("clamps score to 0–100", () => {
    const many = Array.from({ length: 50 }, (_, i) => ({
      severity: (["critical", "high", "medium"] as const)[i % 3],
    }));
    const { score } = calculateScore(many);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("returns critical risk when score < 40", () => {
    const { score, riskLevel } = calculateScore([
      { severity: "critical" },
      { severity: "critical" },
      { severity: "high" },
      { severity: "high" },
    ]);
    expect(score).toBe(32);
    expect(riskLevel).toBe("critical");
  });

  it("returns high risk when score in [40, 60)", () => {
    const { score, riskLevel } = calculateScore([
      { severity: "critical" },
      { severity: "critical" },
    ]);
    expect(score).toBe(56);
    expect(riskLevel).toBe("high");
  });
});

describe("isSpaFallback", () => {
  it("returns true for HTML document with doctype", () => {
    expect(isSpaFallback("<!DOCTYPE html><html>", "text/html")).toBe(true);
    expect(isSpaFallback("<!doctype html><html><body></body></html>", "text/html")).toBe(true);
  });

  it("returns true for HTML starting with <html>", () => {
    expect(isSpaFallback("<html><head></head></html>", "text/html")).toBe(true);
  });

  it("returns false for non-HTML content type", () => {
    expect(isSpaFallback("<!DOCTYPE html>", "application/json")).toBe(false);
    expect(isSpaFallback("<!DOCTYPE html>", "text/plain")).toBe(false);
  });

  it("returns false for plain text body", () => {
    expect(isSpaFallback("DB_PASSWORD=secret", "text/html")).toBe(false);
    expect(isSpaFallback("[core]", "text/html")).toBe(false);
  });
});

describe("hasFileSpecificContent", () => {
  it("detects .env-style content", () => {
    expect(hasFileSpecificContent("/.env", "NODE_ENV=production\nAPI_KEY=abc")).toBe(true);
    expect(hasFileSpecificContent("/.env", "<!DOCTYPE html>")).toBe(false);
  });

  it("detects .git/config content", () => {
    expect(hasFileSpecificContent("/.git/config", "[core]\nrepositoryformatversion = 0")).toBe(true);
    expect(hasFileSpecificContent("/.git/config", "[remote]\nurl = https://github.com/foo")).toBe(true);
    expect(hasFileSpecificContent("/.git/config", "<!DOCTYPE html>")).toBe(false);
  });

  it("detects phpinfo content", () => {
    expect(hasFileSpecificContent("/phpinfo.php", "PHP Version 8.1")).toBe(true);
    expect(hasFileSpecificContent("/phpinfo.php", "Configuration\nphpinfo()")).toBe(true);
  });

  it("detects WordPress admin", () => {
    expect(hasFileSpecificContent("/wp-admin", "wordpress wp-login")).toBe(true);
  });

  it("returns false for SPA fallback on sensitive path", () => {
    expect(hasFileSpecificContent("/.env", "<!doctype html><html>")).toBe(false);
  });
});
