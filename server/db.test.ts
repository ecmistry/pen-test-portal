import { describe, expect, it, vi } from "vitest";

describe("getDb", () => {
  it("returns null when DATABASE_URL is unset", async () => {
    vi.resetModules();
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    const { getDb } = await import("./db");
    const result = await getDb();
    expect(result).toBeNull();
    process.env.DATABASE_URL = original;
  });
});
