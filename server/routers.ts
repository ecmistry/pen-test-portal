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
import type { Scan, ScanFinding, Target } from "../drizzle/schema";
import { generateExecutiveSummary, generateJSONReport, generateMarkdownReport } from "./reportGenerator";
import { generatePdfReport } from "./pdfReport";
import { runScan, analyzeAttackScenarios, type AuthScanConfig, type LoginCredentials } from "./scanEngine";
import { pushFindingsToTicketing, type IntegrationsConfig, type TicketResult } from "./ticketingIntegration";
import { getPenTestCache, updatePenTestCapabilities } from "./penTestUpdater";
import { enrichFinding } from "./findingEnrichment";

// ─── Admin guard ──────────────────────────────────────────────────────────────
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
  return next({ ctx });
});

// ─── Demo report data (public, no auth) ────────────────────────────────────────
function getDemoReportData(): { scan: Scan; target: Target; findings: ScanFinding[]; generatedAt: Date } {
  const generatedAt = new Date();
  const mockScan: Scan = {
    id: 0,
    targetId: 0,
    userId: 0,
    status: "completed",
    tools: "headers,auth,sqli,xss,recon",
    scanMode: "full",
    authMode: null,
    authMeta: null,
    securityScore: 78,
    riskLevel: "medium",
    totalFindings: 3,
    criticalCount: 0,
    highCount: 1,
    mediumCount: 1,
    lowCount: 1,
    infoCount: 0,
    startedAt: new Date(Date.now() - 300000),
    completedAt: new Date(),
    errorMessage: null,
    triggeredBy: "manual",
    scenarios: null,
    trendSummary: null,
    createdAt: new Date(),
  };
  const mockTarget: Target = {
    id: 0,
    userId: 0,
    name: "Demo Application",
    url: "https://demo.example.com",
    description: "Sample target for demo report",
    tags: null,
    scanFrequency: "manual",
    isActive: true,
    lastScannedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  const demoFindings = [
    { category: "Security Headers", severity: "medium" as const, title: "Missing Content-Security-Policy", description: "Content-Security-Policy header is not set, which may increase the risk of XSS and injection attacks.", evidence: "Header 'Content-Security-Policy' not found in response headers", recommendation: "Set a restrictive CSP header (e.g. default-src 'self') to mitigate XSS.", cweId: "CWE-693", owaspCategory: "A05:2021 Security Misconfiguration" },
    { category: "Authentication", severity: "high" as const, title: "No rate limiting on login", description: "Multiple failed login attempts did not trigger lockout or rate limiting.", evidence: "10 consecutive failed login attempts did not trigger lockout or rate limiting", recommendation: "Implement account lockout or rate limiting after N failed attempts.", cweId: "CWE-307", owaspCategory: "A07:2021 Identification and Authentication Failures" },
    { category: "Information Disclosure", severity: "low" as const, title: "Server header reveals version", description: "The Server response header exposes product and version information.", evidence: "Server: Apache/2.4.41", recommendation: "Suppress or genericise the Server header to reduce information disclosure.", cweId: null as string | null, owaspCategory: "A05:2021 Security Misconfiguration" },
  ];
  const mockFindings: ScanFinding[] = demoFindings.map((f, i) => {
    const enriched = enrichFinding(f.category, f.severity, f.cweId);
    return {
      id: i + 1,
      scanId: 0,
      ...f,
      cvssVector: enriched.cvssVector,
      cvssScore: enriched.cvssScore != null ? String(enriched.cvssScore) : null,
      remediationComplexity: enriched.remediationComplexity,
      remediationPriority: enriched.remediationPriority,
      businessImpact: enriched.businessImpact,
      attackTechniques: enriched.attackTechniques,
      iso27001Controls: enriched.iso27001Controls,
      poc: null,
      authContext: null,
      status: "open" as const,
      createdAt: new Date(),
    };
  });
  const scenarios = analyzeAttackScenarios(demoFindings.map((f) => ({ category: f.category, title: f.title })));
  mockScan.scenarios = scenarios.length > 0 ? scenarios : null;
  return { scan: mockScan, target: mockTarget, findings: mockFindings, generatedAt };
}

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
          authProfiles: z.array(z.object({
            name: z.string(),
            type: z.enum(["none", "bearer", "basic"]),
            token: z.string().optional(),
            username: z.string().optional(),
            password: z.string().optional(),
          })).optional(),
          authTests: z.object({
            verticalEscalation: z.boolean().optional(),
            horizontalEscalation: z.boolean().optional(),
            sessionExpiry: z.boolean().optional(),
            tokenReuse: z.boolean().optional(),
          }).optional(),
          manifestPath: z.string().optional(),
          loginCredentials: z.object({
            loginUrl: z.string().url(),
            username: z.string(),
            password: z.string(),
            usernameField: z.string().optional(),
            passwordField: z.string().optional(),
            loginMethod: z.enum(["form", "json"]).optional(),
          }).optional(),
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

        const authConfig: AuthScanConfig | undefined =
          input.authProfiles ? { authProfiles: input.authProfiles, authTests: input.authTests } : undefined;

        const loginCreds: LoginCredentials | undefined = input.loginCredentials;

        setImmediate(() => {
          runScan(scanId, target.id, target.url, input.tools, input.scanMode, authConfig, input.manifestPath, loginCreds).catch(console.error);
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

    pushToTicketing: protectedProcedure
      .input(
        z.object({
          scanId: z.number(),
          dryRun: z.boolean().default(false),
          integrations: z.object({
            jira: z.object({
              enabled: z.boolean(),
              baseUrl: z.string(),
              projectKey: z.string(),
              apiToken: z.string(),
              email: z.string(),
              minSeverity: z.enum(["critical", "high", "medium", "low"]).default("medium"),
              issueType: z.string().optional(),
              labels: z.array(z.string()).optional(),
              deduplication: z.boolean().optional(),
              reopenResolved: z.boolean().optional(),
            }).optional(),
            github: z.object({
              enabled: z.boolean(),
              repo: z.string(),
              token: z.string(),
              minSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),
              labels: z.array(z.string()).optional(),
            }).optional(),
            linear: z.object({
              enabled: z.boolean(),
              apiKey: z.string(),
              teamId: z.string(),
              minSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),
            }).optional(),
          }),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const scan = await getScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(scan.userId, ctx.user);
        const target = await getTargetById(scan.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
        const findings = await getFindingsByScan(input.scanId);
        const results = await pushFindingsToTicketing(input.integrations, findings, target.url, input.dryRun);
        return {
          success: true,
          results,
          summary: {
            total: results.length,
            created: results.filter(r => r.action === "created").length,
            updated: results.filter(r => r.action === "commented" || r.action === "reopened").length,
            skipped: results.filter(r => r.action === "skipped").length,
          },
        };
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

        const complianceNotes = `Standards covered: OWASP Top 10:2021, CVSSv3.1, MITRE ATT&CK, PTES, NIST SP 800-115, CWE Top 25, ISO/IEC 27001. Tools used: ${scan.tools}. Scan completed: ${scan.completedAt?.toISOString() || "N/A"}.`;

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

    getDemoReport: publicProcedure.query(() => {
      const reportData = getDemoReportData();
      const title = `Penetration Test Report — ${reportData.target.name} — ${reportData.generatedAt.toLocaleDateString()} (Demo)`;
      return {
        markdown: generateMarkdownReport(reportData),
        title,
        json: generateJSONReport(reportData),
      };
    }),

    getDemoReportPdf: publicProcedure.query(() => {
      const reportData = getDemoReportData();
      const title = `Penetration Test Report — ${reportData.target.name} — ${reportData.generatedAt.toLocaleDateString()} (Demo)`;
      const pdfBuffer = generatePdfReport(reportData);
      return { pdfBase64: pdfBuffer.toString("base64"), title };
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

  // ─── CI/CD Pipeline ───────────────────────────────────────────────────────
  cicd: router({
    scan: publicProcedure
      .input(z.object({
        targetUrl: z.string().url(),
        tools: z.array(z.string()).default(["headers", "auth", "sqli", "xss", "recon"]),
        scanMode: z.enum(["light", "full"]).default("light"),
        failOn: z.enum(["critical", "high", "medium", "low"]).default("high"),
        apiKey: z.string().min(1),
      }))
      .mutation(async ({ input }) => {
        const expectedKey = process.env.CICD_API_KEY;
        if (!expectedKey || input.apiKey !== expectedKey) {
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid CI/CD API key" });
        }

        const ciUserId = 0;
        const ciTargetId = 0;

        const allFindings: Array<{ category: string; severity: string; title: string; cvssScore?: number | null }> = [];
        const { runScan: runScanFn } = await import("./scanEngine");
        const { createScan: createScanFn, getScanById: getScanByIdFn, getFindingsByScan: getFindingsByIdFn } = await import("./db");

        const scanId = await createScanFn({
          targetId: ciTargetId,
          userId: ciUserId,
          tools: input.tools.join(","),
          scanMode: input.scanMode,
          triggeredBy: "manual",
        });

        await runScanFn(scanId, ciTargetId, input.targetUrl, input.tools, input.scanMode);

        const scan = await getScanByIdFn(scanId);
        const findings = await getFindingsByIdFn(scanId);

        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const threshold = severityOrder[input.failOn] ?? 1;
        const failFindings = findings.filter((f) => (severityOrder[f.severity] ?? 4) <= threshold);
        const pass = failFindings.length === 0;

        return {
          pass,
          exitCode: pass ? 0 : 1,
          scanId,
          targetUrl: input.targetUrl,
          securityScore: scan?.securityScore ?? 0,
          securityGrade: (() => { const s = scan?.securityScore ?? 0; return s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 55 ? "D" : "F"; })(),
          riskLevel: scan?.riskLevel ?? "unknown",
          threshold: input.failOn,
          totalFindings: findings.length,
          failingFindings: failFindings.length,
          bySeverity: {
            critical: findings.filter((f) => f.severity === "critical").length,
            high: findings.filter((f) => f.severity === "high").length,
            medium: findings.filter((f) => f.severity === "medium").length,
            low: findings.filter((f) => f.severity === "low").length,
            info: findings.filter((f) => f.severity === "info").length,
          },
          findings: findings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            cvssScore: f.cvssScore ? Number(f.cvssScore) : null,
            cweId: f.cweId,
            recommendation: f.recommendation,
          })),
          summary: `${pass ? "PASS" : "FAIL"} — ${findings.length} finding(s), ${failFindings.length} at or above ${input.failOn} severity. Score: ${scan?.securityScore ?? 0}/100 (Grade ${(() => { const s = scan?.securityScore ?? 0; return s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 55 ? "D" : "F"; })()}).`,
        };
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
