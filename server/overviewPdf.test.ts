import { describe, expect, it } from "vitest";
import { generateOverviewPdf } from "./overviewPdf";

describe("generateOverviewPdf", () => {
  it("returns a valid PDF buffer with overview content", () => {
    const buf = generateOverviewPdf(new Date("2026-01-15T12:00:00Z"));
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    const text = buf.toString("latin1");
    expect(text).toContain("Ghoststrike");
  });

  it("produces a multi-page document", () => {
    const buf = generateOverviewPdf();
    // PDF with multiple pages typically contains more than one /Type /Page
    const matches = buf.toString("latin1").match(/\/Type\s*\/Page[^s]/g) ?? [];
    expect(matches.length).toBeGreaterThanOrEqual(2);
  });
});
