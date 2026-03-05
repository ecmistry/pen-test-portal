import { describe, expect, it, vi } from "vitest";
import type { TrpcContext } from "./_core/context";

const mockDb = vi.hoisted(() => {
  const names = [
    "createReport", "createScan", "createSchedule", "createTarget", "deleteSchedule", "deleteTarget",
    "getAllReports", "getAllScans", "getAllTargets", "getAllUsers", "getDashboardStats", "getFindingsByScan",
    "getLogsByScan", "getRecentFindingsByUser", "getReportByScan", "getReportsByUser", "getScanById",
    "getScanTrends", "getScansByTarget", "getScansByUser", "getSchedulesByUser", "getTargetById",
    "getTargetsByUser", "updateFindingStatus", "updateSchedule", "updateTarget", "updateUserRole",
  ];
  return Object.fromEntries(names.map((n) => [n, vi.fn()]));
});

vi.mock("./db", () => mockDb);

vi.mock("./scanEngine", async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    runScan: vi.fn().mockResolvedValue(undefined),
  };
});

vi.mock("./penTestUpdater", () => ({
  getPenTestCache: vi.fn(),
  updatePenTestCapabilities: vi.fn(),
}));

import { appRouter } from "./routers";
import * as db from "./db";

const mockUser = {
  id: 1,
  openId: "user-1",
  email: "user@test.com",
  name: "Test User",
  loginMethod: "oauth" as const,
  role: "user" as const,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

const mockAdminUser = { ...mockUser, id: 2, role: "admin" as const };

const mockTarget = {
  id: 10,
  userId: 1,
  name: "Test Target",
  url: "https://example.com",
  description: null,
  tags: null,
  scanFrequency: "manual" as const,
  isActive: true,
  lastScannedAt: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockScan = {
  id: 100,
  targetId: 10,
  userId: 1,
  status: "completed" as const,
  tools: "headers,auth,sqli,xss",
  scanMode: "light" as const,
  securityScore: 85,
  riskLevel: "low" as const,
  totalFindings: 2,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 1,
  lowCount: 1,
  infoCount: 0,
  startedAt: new Date(),
  completedAt: new Date(),
  errorMessage: null,
  triggeredBy: "manual" as const,
  scenarios: null,
  trendSummary: null,
  createdAt: new Date(),
};

function createContext(user: typeof mockUser | null): TrpcContext {
  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

describe("auth.me", () => {
  it("returns null when unauthenticated", async () => {
    const ctx = createContext(null);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.auth.me();
    expect(result).toBeNull();
  });

  it("returns user when authenticated", async () => {
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.auth.me();
    expect(result).toEqual(mockUser);
  });
});

describe("targets.list", () => {
  it("returns targets for non-admin user via getTargetsByUser", async () => {
    vi.mocked(db.getTargetsByUser).mockResolvedValueOnce([mockTarget]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.targets.list();
    expect(result).toHaveLength(1);
    expect(result[0]?.name).toBe("Test Target");
  });

  it("returns all targets for admin via getAllTargets", async () => {
    vi.mocked(db.getAllTargets).mockResolvedValueOnce([mockTarget, { ...mockTarget, id: 11 }]);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.targets.list();
    expect(result).toHaveLength(2);
  });
});

describe("targets.get", () => {
  it("returns target when user owns it", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(mockTarget);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.targets.get({ id: 10 });
    expect(result?.id).toBe(10);
    expect(result?.url).toBe("https://example.com");
  });

  it("throws NOT_FOUND when target does not exist", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.targets.get({ id: 999 })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
  });
});

describe("scans.get", () => {
  it("returns scan when user owns it", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.get({ id: 100 });
    expect(result?.id).toBe(100);
    expect(result?.status).toBe("completed");
  });

  it("throws NOT_FOUND when scan does not exist", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.scans.get({ id: 999 })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
  });
});

describe("scans.start", () => {
  it("creates scan and returns scanId when user owns target", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(mockTarget);
    vi.mocked(db.createScan).mockResolvedValueOnce(101 as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.start({ targetId: 10, tools: ["headers"], scanMode: "light" });
    expect(result.scanId).toBe(101);
    expect(result.success).toBe(true);
  });
});

describe("scans.list", () => {
  it("returns scans for user when no targetId", async () => {
    vi.mocked(db.getScansByUser).mockResolvedValueOnce([mockScan]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.list({});
    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe(100);
  });
});

describe("protectedProcedure", () => {
  it("throws UNAUTHORIZED when user is null", async () => {
    const ctx = createContext(null as any);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.targets.list()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});

describe("adminProcedure", () => {
  it("throws FORBIDDEN when user is not admin", async () => {
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.admin.users()).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});

describe("reports.list", () => {
  it("returns reports for user", async () => {
    vi.mocked(db.getReportsByUser).mockResolvedValueOnce([]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.reports.list();
    expect(result).toEqual([]);
  });
});

describe("reports.getByScan", () => {
  it("returns report when user owns scan", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getReportByScan).mockResolvedValueOnce({ id: 1, scanId: 100, title: "Report", executiveSummary: "", markdownContent: "", jsonContent: "", complianceNotes: "", userId: 1, createdAt: new Date() } as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.reports.getByScan({ scanId: 100 });
    expect(result).toBeDefined();
  });
});

describe("scans.logs", () => {
  it("returns logs when user owns scan", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getLogsByScan).mockResolvedValueOnce([{ id: 1, scanId: 100, level: "info", message: "Test", phase: null, createdAt: new Date() }]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.logs({ scanId: 100 });
    expect(result).toHaveLength(1);
  });
});

describe("scans.findings", () => {
  it("returns findings when user owns scan", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getFindingsByScan).mockResolvedValueOnce([]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.findings({ scanId: 100 });
    expect(result).toEqual([]);
  });
});

describe("dashboard", () => {
  it("returns stats for user", async () => {
    vi.mocked(db.getDashboardStats).mockResolvedValueOnce({ totalTargets: 1, totalScans: 2, recentFindings: 0 } as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.dashboard.stats();
    expect(result).toBeDefined();
  });

  it("returns recentScans for user", async () => {
    vi.mocked(db.getScansByUser).mockResolvedValueOnce([mockScan]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.dashboard.recentScans();
    expect(result).toHaveLength(1);
  });
});

describe("admin", () => {
  it("returns users for admin", async () => {
    vi.mocked(db.getAllUsers).mockResolvedValueOnce([mockUser]);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.admin.users();
    expect(result).toHaveLength(1);
  });

  it("updateUserRole succeeds", async () => {
    vi.mocked(db.updateUserRole).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.admin.updateUserRole({ userId: 2, role: "admin" });
    expect(result).toEqual({ success: true });
  });

  it("allScans returns scans for admin", async () => {
    vi.mocked(db.getAllScans).mockResolvedValueOnce([mockScan]);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.admin.allScans({ limit: 50 });
    expect(result).toHaveLength(1);
  });

  it("allTargets returns targets for admin", async () => {
    vi.mocked(db.getAllTargets).mockResolvedValueOnce([mockTarget]);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.admin.allTargets();
    expect(result).toHaveLength(1);
  });

  it("getScanCapabilitiesStatus returns cache", async () => {
    const { getPenTestCache } = await import("./penTestUpdater");
    vi.mocked(getPenTestCache).mockResolvedValueOnce({ lastUpdated: "2025-01-01", payloads: {}, nuclei: {} } as any);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.admin.getScanCapabilitiesStatus();
    expect(result).toBeDefined();
  });

  it("updateScanCapabilities runs", async () => {
    const { updatePenTestCapabilities } = await import("./penTestUpdater");
    vi.mocked(updatePenTestCapabilities).mockResolvedValueOnce({ success: true } as any);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.admin.updateScanCapabilities();
    expect(result).toBeDefined();
  });
});

describe("reports.getDemoReport (public)", () => {
  it("returns markdown, title, and json without auth", async () => {
    const ctx = createContext(null);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.reports.getDemoReport();
    expect(result.title).toBeDefined();
    expect(result.title).toContain("Demo");
    expect(result.markdown).toBeDefined();
    expect(result.markdown).toContain("Penetration Test Report");
    expect(result.json).toBeDefined();
    expect((result.json as any).summary?.securityScore).toBe(78);
  });
});

describe("reports.getDemoReportPdf (public)", () => {
  it("returns pdfBase64 and title without auth", async () => {
    const ctx = createContext(null);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.reports.getDemoReportPdf();
    expect(result.title).toBeDefined();
    expect(result.pdfBase64).toBeDefined();
    expect(Buffer.from(result.pdfBase64, "base64").subarray(0, 5).toString("ascii")).toBe("%PDF-");
  });
});

// ─── auth.logout ─────────────────────────────────────────────────────────────

describe("auth.logout", () => {
  it("returns { success: true } and clears cookie", async () => {
    const clearCookieSpy = vi.fn();
    const ctx = {
      user: null,
      req: { protocol: "https", headers: {} } as any,
      res: { clearCookie: clearCookieSpy } as any,
    };
    const caller = appRouter.createCaller(ctx);
    const result = await caller.auth.logout();
    expect(result).toEqual({ success: true });
    expect(clearCookieSpy).toHaveBeenCalled();
  });
});

// ─── targets CRUD ────────────────────────────────────────────────────────────

describe("targets.create", () => {
  it("creates target and returns success", async () => {
    vi.mocked(db.createTarget).mockResolvedValueOnce(undefined as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.targets.create({
      name: "New Target",
      url: "https://new-example.com",
    });
    expect(result).toEqual({ success: true });
    expect(db.createTarget).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "New Target",
        url: "https://new-example.com",
        userId: 1,
      }),
    );
  });
});

describe("targets.update", () => {
  it("updates target when user owns it", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(mockTarget);
    vi.mocked(db.updateTarget).mockResolvedValueOnce(undefined as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.targets.update({ id: 10, name: "Updated Name" });
    expect(result).toEqual({ success: true });
    expect(db.updateTarget).toHaveBeenCalledWith(10, { name: "Updated Name" });
  });

  it("throws FORBIDDEN when non-owner tries to update", async () => {
    const otherUserTarget = { ...mockTarget, userId: 999 };
    vi.mocked(db.getTargetById).mockResolvedValueOnce(otherUserTarget);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.targets.update({ id: 10, name: "Hacked" })).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("throws NOT_FOUND when target does not exist", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.targets.update({ id: 999, name: "Ghost" })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

describe("targets.delete", () => {
  it("deletes target when user owns it", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(mockTarget);
    vi.mocked(db.deleteTarget).mockResolvedValueOnce(undefined as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.targets.delete({ id: 10 });
    expect(result).toEqual({ success: true });
    expect(db.deleteTarget).toHaveBeenCalledWith(10);
  });

  it("throws FORBIDDEN when non-owner tries to delete", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce({ ...mockTarget, userId: 999 });
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.targets.delete({ id: 10 })).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("throws NOT_FOUND when target does not exist", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.targets.delete({ id: 999 })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

// ─── Ownership: admin access to other user's resources ──────────────────────

describe("assertOwnerOrAdmin — admin override", () => {
  it("admin can access another user's target", async () => {
    vi.mocked(db.getTargetById).mockResolvedValueOnce(mockTarget);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.targets.get({ id: 10 });
    expect(result?.id).toBe(10);
  });

  it("admin can access another user's scan", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    const ctx = createContext(mockAdminUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.get({ id: 100 });
    expect(result?.id).toBe(100);
  });

  it("non-owner non-admin throws FORBIDDEN on target get", async () => {
    const otherUserTarget = { ...mockTarget, userId: 999 };
    vi.mocked(db.getTargetById).mockResolvedValueOnce(otherUserTarget);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.targets.get({ id: 10 })).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("non-owner non-admin throws FORBIDDEN on scan get", async () => {
    const otherUserScan = { ...mockScan, userId: 999 };
    vi.mocked(db.getScanById).mockResolvedValueOnce(otherUserScan);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.scans.get({ id: 100 })).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});

// ─── scans.updateFinding ─────────────────────────────────────────────────────

describe("scans.updateFinding", () => {
  it("updates finding status and returns success", async () => {
    vi.mocked(db.updateFindingStatus).mockResolvedValueOnce(undefined as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.updateFinding({ findingId: 1, status: "resolved" });
    expect(result).toEqual({ success: true });
    expect(db.updateFindingStatus).toHaveBeenCalledWith(1, "resolved");
  });

  it("allows status false_positive", async () => {
    vi.mocked(db.updateFindingStatus).mockResolvedValueOnce(undefined as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.updateFinding({ findingId: 2, status: "false_positive" });
    expect(result).toEqual({ success: true });
  });

  it("allows status acknowledged", async () => {
    vi.mocked(db.updateFindingStatus).mockResolvedValueOnce(undefined as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.updateFinding({ findingId: 3, status: "acknowledged" });
    expect(result).toEqual({ success: true });
  });
});

// ─── scans.recentFindings ────────────────────────────────────────────────────

describe("scans.recentFindings", () => {
  it("returns recent findings for user", async () => {
    vi.mocked(db.getRecentFindingsByUser).mockResolvedValueOnce([]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.scans.recentFindings();
    expect(result).toEqual([]);
    expect(db.getRecentFindingsByUser).toHaveBeenCalledWith(1, 20);
  });
});

// ─── reports.generate ────────────────────────────────────────────────────────

describe("reports.generate", () => {
  it("throws BAD_REQUEST when scan is not completed", async () => {
    const runningScan = { ...mockScan, status: "running" as const };
    vi.mocked(db.getScanById).mockResolvedValueOnce(runningScan);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.reports.generate({ scanId: 100 })).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  it("returns existing reportId if report already exists", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getTargetById).mockResolvedValueOnce(mockTarget);
    vi.mocked(db.getFindingsByScan).mockResolvedValueOnce([]);
    vi.mocked(db.getReportByScan).mockResolvedValueOnce({ id: 42 } as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.reports.generate({ scanId: 100 });
    expect(result).toEqual({ reportId: 42, success: true });
  });

  it("creates new report when none exists", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getTargetById).mockResolvedValueOnce(mockTarget);
    vi.mocked(db.getFindingsByScan).mockResolvedValueOnce([]);
    vi.mocked(db.getReportByScan).mockResolvedValueOnce(undefined);
    vi.mocked(db.createReport).mockResolvedValueOnce(55 as any);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.reports.generate({ scanId: 100 });
    expect(result).toEqual({ reportId: 55, success: true });
    expect(db.createReport).toHaveBeenCalledWith(
      expect.objectContaining({
        scanId: 100,
        userId: 1,
      }),
    );
  });

  it("throws NOT_FOUND when scan does not exist", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.reports.generate({ scanId: 999 })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

// ─── reports.getMarkdown / getPDF / getJSON ─────────────────────────────────

describe("reports.getMarkdown", () => {
  it("throws NOT_FOUND when report not generated", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getReportByScan).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.reports.getMarkdown({ scanId: 100 })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

describe("reports.getPDF", () => {
  it("throws NOT_FOUND when report not generated", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getReportByScan).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.reports.getPDF({ scanId: 100 })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

describe("reports.getJSON", () => {
  it("throws NOT_FOUND when report not generated", async () => {
    vi.mocked(db.getScanById).mockResolvedValueOnce(mockScan);
    vi.mocked(db.getReportByScan).mockResolvedValueOnce(undefined);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    await expect(caller.reports.getJSON({ scanId: 100 })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

// ─── dashboard.trends ────────────────────────────────────────────────────────

describe("dashboard.trends", () => {
  it("returns scan trends for user", async () => {
    vi.mocked(db.getScanTrends).mockResolvedValueOnce([]);
    const ctx = createContext(mockUser);
    const caller = appRouter.createCaller(ctx);
    const result = await caller.dashboard.trends({ days: 30 });
    expect(result).toEqual([]);
    expect(db.getScanTrends).toHaveBeenCalledWith(1, false, 30);
  });
});
