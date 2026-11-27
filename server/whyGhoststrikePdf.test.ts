import { describe, expect, it } from "vitest";
import { generateWhyGhoststrikePdf } from "./whyGhoststrikePdf";

describe("generateWhyGhoststrikePdf", () => {
  it("returns a valid PDF with why-useful content", () => {
    const buf = generateWhyGhoststrikePdf(new Date("2026-11-27T12:00:00Z"));
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    const text = buf.toString("latin1");
    expect(text).toContain("Ghoststrike");
    expect(text).toMatch(/useful|Useful/);
  });
});
