import { describe, expect, it, vi } from "vitest";

describe("notifyOwner", () => {
  it("returns true when fetch succeeds", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce({ ok: true })
    );
    vi.resetModules();
    process.env.BUILT_IN_FORGE_API_URL = "https://api.test/";
    process.env.BUILT_IN_FORGE_API_KEY = "key";
    const { notifyOwner } = await import("./notification");
    const result = await notifyOwner({ title: "Test", content: "Body" });
    expect(result).toBe(true);
    vi.unstubAllGlobals();
  });

  it("returns false when response not ok", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Error",
        text: () => Promise.resolve(""),
      })
    );
    vi.resetModules();
    process.env.BUILT_IN_FORGE_API_URL = "https://api.test/";
    process.env.BUILT_IN_FORGE_API_KEY = "key";
    const { notifyOwner } = await import("./notification");
    const result = await notifyOwner({ title: "T", content: "C" });
    expect(result).toBe(false);
    vi.unstubAllGlobals();
  });

  it("throws when forgeApiUrl is not configured", async () => {
    vi.resetModules();
    const orig = process.env.BUILT_IN_FORGE_API_URL;
    const origKey = process.env.GEMINI_API_KEY;
    delete process.env.BUILT_IN_FORGE_API_URL;
    delete process.env.GEMINI_API_KEY;
    const { notifyOwner } = await import("./notification");
    await expect(notifyOwner({ title: "T", content: "C" })).rejects.toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      message: /Notification service URL/,
    });
    process.env.BUILT_IN_FORGE_API_URL = orig;
    process.env.GEMINI_API_KEY = origKey;
  });

  it("throws when title is empty", async () => {
    vi.resetModules();
    const { notifyOwner } = await import("./notification");
    await expect(notifyOwner({ title: "  ", content: "C" })).rejects.toMatchObject({
      code: "BAD_REQUEST",
      message: /title/,
    });
  });

  it("returns false when fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce(new Error("Network error")));
    vi.resetModules();
    process.env.BUILT_IN_FORGE_API_URL = "https://api.test/";
    process.env.BUILT_IN_FORGE_API_KEY = "key";
    const { notifyOwner } = await import("./notification");
    const result = await notifyOwner({ title: "T", content: "C" });
    expect(result).toBe(false);
    vi.unstubAllGlobals();
  });

  it("throws when content is empty", async () => {
    vi.resetModules();
    const { notifyOwner } = await import("./notification");
    await expect(notifyOwner({ title: "T", content: "" })).rejects.toMatchObject({
      code: "BAD_REQUEST",
      message: /content/,
    });
  });
});
