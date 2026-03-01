import { describe, expect, it, vi } from "vitest";

vi.mock("fs/promises", () => ({
  default: {
    readFile: vi.fn(),
  },
}));

vi.mock("./notification", () => ({
  notifyOwner: vi.fn(),
}));

import fs from "fs/promises";
import { appRouter } from "../routers";
import type { TrpcContext } from "./context";
import { notifyOwner } from "./notification";

const adminUser = {
  id: 1,
  openId: "admin-1",
  email: "admin@test.com",
  name: "Admin",
  loginMethod: "admin" as const,
  role: "admin" as const,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

function createContext(user: TrpcContext["user"]): TrpcContext {
  return {
    user,
    req: {} as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

describe("system.getMethodology", () => {
  it("returns file content when docs/PENTEST_METHODOLOGY.md exists", async () => {
    vi.mocked(fs.readFile).mockResolvedValueOnce("# Methodology\n\nContent here.");
    const ctx = createContext(null);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.system.getMethodology();
    expect(result).toContain("Methodology");
    expect(result).toContain("Content here.");
  });

  it("returns fallback when file read fails", async () => {
    vi.mocked(fs.readFile).mockRejectedValueOnce(new Error("ENOENT"));
    const ctx = createContext(null);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.system.getMethodology();
    expect(result).toContain("Methodology document not found");
    expect(result).toContain("PENTEST_METHODOLOGY");
  });
});

describe("system.health", () => {
  it("returns ok true with valid input", async () => {
    const ctx = createContext(null);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.system.health({ timestamp: Date.now() });
    expect(result).toEqual({ ok: true });
  });
});

describe("system.notifyOwner", () => {
  it("returns success when notifyOwner delivers", async () => {
    vi.mocked(notifyOwner).mockResolvedValueOnce(true);
    const ctx = createContext(adminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.system.notifyOwner({ title: "Test", content: "Body" });
    expect(result).toEqual({ success: true });
  });

  it("returns success false when notifyOwner fails", async () => {
    vi.mocked(notifyOwner).mockResolvedValueOnce(false);
    const ctx = createContext(adminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.system.notifyOwner({ title: "Test", content: "Body" });
    expect(result).toEqual({ success: false });
  });
});
