import { describe, expect, it, vi } from "vitest";

describe("ENV.forgeApiUrl", () => {
  it("uses GEMINI_API_KEY fallback when BUILT_IN_FORGE_API_URL is unset", async () => {
    vi.resetModules();
    const orig = process.env.BUILT_IN_FORGE_API_URL;
    const origGemini = process.env.GEMINI_API_KEY;
    delete process.env.BUILT_IN_FORGE_API_URL;
    process.env.GEMINI_API_KEY = "test-key";
    const { ENV } = await import("./env");
    expect(ENV.forgeApiUrl).toContain("generativelanguage.googleapis.com");
    process.env.BUILT_IN_FORGE_API_URL = orig;
    process.env.GEMINI_API_KEY = origGemini;
  });
});
