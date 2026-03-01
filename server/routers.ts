import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import {
  createReport,
  createScan,
  createSchedule,
  createTarget,
  deleteSchedule,
  deleteTarget,
  getAllReports,
  getAllScans,
  getAllTargets,
  getAllUsers,
  getDashboardStats,
  getFindingsByScan,
  getLogsByScan,
  getRecentFindingsByUser,
  getReportByScan,
  getReportsByUser,
  getScanById,
  getScanTrends,
  getScansByTarget,
  getScansByUser,
  getSchedulesByUser,
  getTargetById,
  getTargetsByUser,
  updateFindingStatus,
  updateSchedule,
  updateTarget,
  updateUserRole,
} from "./db";
import { generateExecutiveSummary, generateJSONReport, generateMarkdownReport } from "./reportGenerator";
import { generatePdfReport } from "./pdfReport";
import { runScan } from "./scanEngine";
import { getPenTestCache, updatePenTestCapabilities } from "./penTestUpdater";

// ─── Admin guard ──────────────────────────────────────────────────────────────
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
  return next({ ctx });
});

// ─── Ownership guard helper ───────────────────────────────────────────────────
function assertOwnerOrAdmin(resourceUserId: number, ctxUser: { id: number; role: string }) {
  if (ctxUser.role !== "admin" && resourceUserId !== ctxUser.id) {
    throw new TRPCError({ code: "FORBIDDEN", message: "Access denied" });
  }
}

export const appRouter = router({
  system: systemRouter,

  // ─── Auth ─────────────────────────────────────────────────────────────────
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  // ─── Targets ──────────────────────────────────────────────────────────────
  targets: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      if (ctx.user.role === "admin") return getAllTargets();
      return getTargetsByUser(ctx.user.id);
    }),

    get: protectedProcedure.input(z.object({ id: z.number() })).query(async ({ ctx, input }) => {
      const target = await getTargetById(input.id);
      if (!target) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(target.userId, ctx.user);
      return target;
    }),

    create: protectedProcedure
      .input(
        z.object({
          name: z.string().min(1).max(255),
          url: z.string().url(),
          description: z.string().optional(),
          tags: z.string().optional(),
          scanFrequency: z.enum(["manual", "daily", "weekly", "monthly"]).default("manual"),
        })
      )
      .mutation(async ({ ctx, input }) => {
        await createTarget({ ...input, userId: ctx.user.id });
        return { success: true };
      }),

    update: protectedProcedure
      .input(
        z.object({
          id: z.number(),
          name: z.string().min(1).max(255).optional(),
          url: z.string().url().optional(),
          description: z.string().optional(),
          tags: z.string().optional(),
          scanFrequency: z.enum(["manual", "daily", "weekly", "monthly"]).optional(),
          isActive: z.boolean().optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { id, ...data } = input;
        const target = await getTargetById(id);
        if (!target) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(target.userId, ctx.user);
        await updateTarget(id, data);
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const target = await getTargetById(input.id);
        if (!target) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(target.userId, ctx.user);
        await deleteTarget(input.id);
        return { success: true };
      }),
  }),

  // ─── Scans ────────────────────────────────────────────────────────────────
  scans: router({
    list: protectedProcedure
      .input(z.object({ targetId: z.number().optional(), limit: z.number().default(50) }))
      .query(async ({ ctx, input }) => {
        if (input.targetId) {
          const target = await getTargetById(input.targetId);
          if (target) assertOwnerOrAdmin(target.userId, ctx.user);
          return getScansByTarget(input.targetId, input.limit);
        }
        if (ctx.user.role === "admin") return getAllScans(input.limit);
        return getScansByUser(ctx.user.id, input.limit);
      }),

    get: protectedProcedure.input(z.object({ id: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.id);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(scan.userId, ctx.user);
      return scan;
    }),

    start: protectedProcedure
      .input(
        z.object({
          targetId: z.number(),
          tools: z.array(z.string()).default(["headers", "auth", "sqli", "xss"]),
          scanMode: z.enum(["light", "full"]).default("light"),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const target = await getTargetById(input.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
        assertOwnerOrAdmin(target.userId, ctx.user);

        const toolsStr = input.tools.join(",");
        const scanId = await createScan({
          targetId: input.targetId,
          userId: ctx.user.id,
          status: "queued",
          tools: toolsStr,
          scanMode: input.scanMode,
          triggeredBy: "manual",
        });

        // Run scan asynchronously (non-blocking)
        setImmediate(() => {
          runScan(scanId, target.id, target.url, input.tools, input.scanMode).catch(console.error);
        });

        return { scanId, success: true };
      }),

    logs: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(scan.userId, ctx.user);
      return getLogsByScan(input.scanId);
    }),

    findings: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(scan.userId, ctx.user);
      return getFindingsByScan(input.scanId);
    }),

    updateFinding: protectedProcedure
      .input(
        z.object({
          findingId: z.number(),
          status: z.enum(["open", "acknowledged", "resolved", "false_positive"]),
        })
      )
      .mutation(async ({ ctx, input }) => {
        await updateFindingStatus(input.findingId, input.status);
        return { success: true };
      }),

    recentFindings: protectedProcedure.query(async ({ ctx }) => {
      return getRecentFindingsByUser(ctx.user.id, 20);
    }),
  }),

  // ─── Reports ──────────────────────────────────────────────────────────────
  reports: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      if (ctx.user.role === "admin") return getAllReports();
      return getReportsByUser(ctx.user.id);
    }),

    getByScan: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(scan.userId, ctx.user);
      const report = await getReportByScan(input.scanId);
      return report ?? null;
    }),

    generate: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const scan = await getScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });
        assertOwnerOrAdmin(scan.userId, ctx.user);

        if (scan.status !== "completed") {
          throw new TRPCError({ code: "BAD_REQUEST", message: "Scan must be completed before generating a report" });
        }

        const target = await getTargetById(scan.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });

        const findings = await getFindingsByScan(input.scanId);
        const generatedAt = new Date();

        const reportData = { scan, target, findings, generatedAt };
        const markdownContent = generateMarkdownReport(reportData);
        const executiveSummary = generateExecutiveSummary(reportData);
        const jsonContent = generateJSONReport(reportData);

        const complianceNotes = `Standards covered: OWASP Top 10:2021, PTES, NIST SP 800-115, CWE Top 25. Tools used: ${scan.tools}. Scan completed: ${scan.completedAt?.toISOString() || "N/A"}.`;

        const existing = await getReportByScan(input.scanId);
        if (existing) return { reportId: existing.id, success: true };

        const reportId = await createReport({
          scanId: input.scanId,
          userId: ctx.user.id,
          title: `Penetration Test Report — ${target.name} — ${generatedAt.toLocaleDateString()}`,
          executiveSummary,
          markdownContent,
          jsonContent,
          complianceNotes,
        });

        return { reportId, success: true };
      }),

    getMarkdown: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(scan.userId, ctx.user);
      const report = await getReportByScan(input.scanId);
      if (!report) throw new TRPCError({ code: "NOT_FOUND", message: "Report not generated yet" });
      return { markdown: report.markdownContent, title: report.title };
    }),

    getJSON: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(scan.userId, ctx.user);
      const report = await getReportByScan(input.scanId);
      if (!report) throw new TRPCError({ code: "NOT_FOUND", message: "Report not generated yet" });
      return { json: report.jsonContent, title: report.title };
    }),

    getPDF: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrAdmin(scan.userId, ctx.user);
      const report = await getReportByScan(input.scanId);
      if (!report) throw new TRPCError({ code: "NOT_FOUND", message: "Report not generated yet" });
      const target = await getTargetById(scan.targetId);
      if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
      const findings = await getFindingsByScan(input.scanId);
      const reportData = { scan, target, findings, generatedAt: report.generatedAt ?? new Date() };
      const pdfBuffer = generatePdfReport(reportData);
      return { pdfBase64: pdfBuffer.toString("base64"), title: report.title };
    }),
  }),

  // ─── Schedules ────────────────────────────────────────────────────────────
  schedules: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      return getSchedulesByUser(ctx.user.id);
    }),

    create: protectedProcedure
      .input(
        z.object({
          targetId: z.number(),
          cronExpression: z.string().min(1),
          tools: z.array(z.string()).default(["headers", "auth", "sqli", "xss"]),
          enabled: z.boolean().default(true),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const target = await getTargetById(input.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(target.userId, ctx.user);

        await createSchedule({
          targetId: input.targetId,
          userId: ctx.user.id,
          cronExpression: input.cronExpression,
          tools: input.tools.join(","),
          enabled: input.enabled,
        });
        return { success: true };
      }),

    update: protectedProcedure
      .input(
        z.object({
          id: z.number(),
          cronExpression: z.string().optional(),
          tools: z.array(z.string()).optional(),
          enabled: z.boolean().optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { id, tools, ...rest } = input;
        const data: Record<string, unknown> = { ...rest };
        if (tools) data.tools = tools.join(",");
        await updateSchedule(id, data as any);
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        await deleteSchedule(input.id);
        return { success: true };
      }),
  }),

  // ─── Dashboard ────────────────────────────────────────────────────────────
  dashboard: router({
    stats: protectedProcedure.query(async ({ ctx }) => {
      return getDashboardStats(ctx.user.id, ctx.user.role === "admin");
    }),

    trends: protectedProcedure
      .input(z.object({ days: z.number().default(30) }))
      .query(async ({ ctx, input }) => {
        return getScanTrends(ctx.user.id, ctx.user.role === "admin", input.days);
      }),

    recentScans: protectedProcedure.query(async ({ ctx }) => {
      if (ctx.user.role === "admin") return getAllScans(10);
      return getScansByUser(ctx.user.id, 10);
    }),
  }),

  // ─── Admin ────────────────────────────────────────────────────────────────
  admin: router({
    users: adminProcedure.query(async () => {
      return getAllUsers();
    }),

    updateUserRole: adminProcedure
      .input(z.object({ userId: z.number(), role: z.enum(["user", "admin"]) }))
      .mutation(async ({ input }) => {
        await updateUserRole(input.userId, input.role);
        return { success: true };
      }),

    globalStats: adminProcedure.query(async () => {
      return getDashboardStats(0, true);
    }),

    allScans: adminProcedure
      .input(z.object({ limit: z.number().default(100) }))
      .query(async ({ input }) => {
        return getAllScans(input.limit);
      }),

    allTargets: adminProcedure.query(async () => {
      return getAllTargets();
    }),

    updateScanCapabilities: adminProcedure.mutation(async () => {
      return updatePenTestCapabilities();
    }),

    getScanCapabilitiesStatus: adminProcedure.query(async () => {
      return getPenTestCache();
    }),
  }),
});

export type AppRouter = typeof appRouter;
