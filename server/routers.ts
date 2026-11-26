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
  getFindingById,
  getFindingsByScan,
  getLogsByScan,
  getRecentFindingsByUser,
  getReportByScan,
  getReportsByUser,
  getScanById,
  getScanTrends,
  getScansByTarget,
  getScansByUser,
  getScheduleById,
  getSchedulesByUser,
  getTargetById,
  getTargetsByUser,
  deleteIntegration,
  getIntegrationByUser,
  updateFindingStatus,
  updateSchedule,
  updateTarget,
  updateUserRole,
  upsertIntegration,
} from "./db";
import type { Scan, ScanFinding, Target } from "../drizzle/schema";
import { generateExecutiveSummary, generateJSONReport, generateMarkdownReport } from "./reportGenerator";
import { generatePdfReport } from "./pdfReport";
import { runScan, analyzeAttackScenarios, type AuthScanConfig, type LoginCredentials } from "./scanEngine";
import { pushFindingsToTicketing, type IntegrationsConfig, type TicketResult } from "./ticketingIntegration";
import { getPenTestCache, updatePenTestCapabilities } from "./penTestUpdater";
import { enrichFinding } from "./findingEnrichment";
import { assertSafeOutboundUrl, isHttpUrl } from "./netSafety";
import { safeEqual } from "./_core/security";
import {
  decryptIntegrationsConfig,
  encryptIntegrationsConfig,
  redactIntegrationsConfig,
} from "./integrationsCrypto";
import { LIGHT_DEFAULT_TOOLS } from "@shared/scanTools";

const httpUrl = z.string().max(2048).url().refine(isHttpUrl, "URL must use http or https");
const httpsUrl = z.string().max(2048).url().refine(u => u.startsWith("https://") && isHttpUrl(u), "URL must use https");
const toolList = z.array(z.string().max(64)).max(64);

const authProfileSchema = z.object({
  name: z.string().max(255),
  type: z.enum(["none", "bearer", "basic"]),
  token: z.string().max(8192).optional(),
  username: z.string().max(255).optional(),
  password: z.string().max(1024).optional(),
  privilegeRank: z.number().int().min(0).max(4).optional(),
});

const authTestsSchema = z.object({
  verticalEscalation: z.boolean().optional(),
  horizontalEscalation: z.boolean().optional(),
  sessionExpiry: z.boolean().optional(),
  tokenReuse: z.boolean().optional(),
});

const loginCredentialsSchema = z.object({
  loginUrl: httpUrl,
  username: z.string().max(255),
  password: z.string().max(1024),
  usernameField: z.string().max(255).optional(),
  passwordField: z.string().max(255).optional(),
  loginMethod: z.enum(["form", "json"]).optional(),
});

const authConfigSchema = z.object({
  authProfiles: z.array(authProfileSchema).max(10).optional(),
  authTests: authTestsSchema.optional(),
  loginCredentials: loginCredentialsSchema.optional(),
});

const integrationsConfigSchema = z.object({
  jira: z.object({
    enabled: z.boolean(),
    baseUrl: httpsUrl,
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
    repo: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "repo must be owner/name"),
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
});
const listLimit = z.number().int().min(1).max(500);

async function assertSafeUrlInput(url: string, protocols?: string[]) {
  try {
    await assertSafeOutboundUrl(url, { protocols });
  } catch (err) {
    throw new TRPCError({ code: "BAD_REQUEST", message: (err as Error).message });
  }
}

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
    repoUrl: null,
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
      affectedUrl: null,
      affectedComponent: null,
      sourceFile: null,
      sourceLine: null,
      sourceSnippet: null,
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
          url: httpUrl,
          repoUrl: httpsUrl.optional().or(z.literal("")),
          description: z.string().max(5000).optional(),
          tags: z.string().max(1000).optional(),
          scanFrequency: z.enum(["manual", "daily", "weekly", "monthly"]).default("manual"),
          openapiUrl: httpUrl.optional().or(z.literal("")),
          manifestPath: z.string().max(500).optional().or(z.literal("")),
          authConfig: authConfigSchema.optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        await assertSafeUrlInput(input.url);
        if (input.repoUrl) await assertSafeUrlInput(input.repoUrl, ["https:"]);
        if (input.openapiUrl) await assertSafeUrlInput(input.openapiUrl);
        if (input.authConfig?.loginCredentials) await assertSafeUrlInput(input.authConfig.loginCredentials.loginUrl);
        const { openapiUrl, manifestPath, authConfig, ...rest } = input;
        await createTarget({
          ...rest,
          userId: ctx.user.id,
          openapiUrl: openapiUrl || null,
          manifestPath: manifestPath || null,
          authConfig: authConfig ?? null,
        });
        return { success: true };
      }),

    update: protectedProcedure
      .input(
        z.object({
          id: z.number(),
          name: z.string().min(1).max(255).optional(),
          url: httpUrl.optional(),
          repoUrl: httpsUrl.optional().or(z.literal("")).or(z.null()),
          description: z.string().max(5000).optional(),
          tags: z.string().max(1000).optional(),
          scanFrequency: z.enum(["manual", "daily", "weekly", "monthly"]).optional(),
          isActive: z.boolean().optional(),
          openapiUrl: httpUrl.optional().or(z.literal("")).or(z.null()),
          manifestPath: z.string().max(500).optional().or(z.literal("")).or(z.null()),
          authConfig: authConfigSchema.nullable().optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const { id, ...data } = input;
        const target = await getTargetById(id);
        if (!target) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(target.userId, ctx.user);
        if (data.url) await assertSafeUrlInput(data.url);
        if (data.repoUrl) await assertSafeUrlInput(data.repoUrl, ["https:"]);
        if (data.openapiUrl) await assertSafeUrlInput(data.openapiUrl);
        if (data.authConfig && typeof data.authConfig === "object" && data.authConfig !== null && "loginCredentials" in data.authConfig) {
          const lc = (data.authConfig as AuthScanConfig).loginCredentials;
          if (lc) await assertSafeUrlInput(lc.loginUrl);
        }
        const patch: Record<string, unknown> = { ...data };
        if (patch.openapiUrl === "") patch.openapiUrl = null;
        if (patch.manifestPath === "") patch.manifestPath = null;
        if (patch.repoUrl === "") patch.repoUrl = null;
        await updateTarget(id, patch as any);
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
      .input(z.object({ targetId: z.number().optional(), limit: listLimit.default(50) }))
      .query(async ({ ctx, input }) => {
        if (input.targetId !== undefined) {
          const target = await getTargetById(input.targetId);
          if (!target) throw new TRPCError({ code: "NOT_FOUND" });
          assertOwnerOrAdmin(target.userId, ctx.user);
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
          tools: toolList.default([...LIGHT_DEFAULT_TOOLS]),
          scanMode: z.enum(["light", "full"]).default("light"),
          authProfiles: z.array(authProfileSchema).max(10).optional(),
          authTests: authTestsSchema.optional(),
          manifestPath: z.string().max(500).optional(),
          loginCredentials: loginCredentialsSchema.optional(),
          useTargetAuthConfig: z.boolean().default(true),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const target = await getTargetById(input.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
        assertOwnerOrAdmin(target.userId, ctx.user);
        await assertSafeUrlInput(target.url);
        if (input.loginCredentials) await assertSafeUrlInput(input.loginCredentials.loginUrl);

        const toolsStr = input.tools.join(",");
        const scanId = await createScan({
          targetId: input.targetId,
          userId: ctx.user.id,
          status: "queued",
          tools: toolsStr,
          scanMode: input.scanMode,
          triggeredBy: "manual",
        });

        const storedAuth = (target.authConfig ?? undefined) as AuthScanConfig | undefined;
        const authConfig: AuthScanConfig | undefined =
          input.authProfiles
            ? { authProfiles: input.authProfiles, authTests: input.authTests }
            : input.useTargetAuthConfig
              ? storedAuth
              : undefined;

        const loginCreds: LoginCredentials | undefined =
          input.loginCredentials ??
          (input.useTargetAuthConfig ? storedAuth?.loginCredentials : undefined);

        const manifestPath =
          input.manifestPath ??
          (target as Target & { manifestPath?: string | null }).manifestPath ??
          undefined;
        const openapiUrl = (target as Target & { openapiUrl?: string | null }).openapiUrl ?? undefined;

        setImmediate(() => {
          runScan(
            scanId,
            target.id,
            target.url,
            input.tools,
            input.scanMode,
            authConfig,
            manifestPath ?? undefined,
            loginCreds,
            target.repoUrl ?? undefined,
            openapiUrl ?? undefined
          ).catch(console.error);
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
        const finding = await getFindingById(input.findingId);
        if (!finding) throw new TRPCError({ code: "NOT_FOUND" });
        const scan = await getScanById(finding.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(scan.userId, ctx.user);
        await updateFindingStatus(input.findingId, input.status);
        return { success: true };
      }),

    pushToTicketing: protectedProcedure
      .input(
        z.object({
          scanId: z.number(),
          dryRun: z.boolean().default(false),
          useStored: z.boolean().default(true),
          integrations: integrationsConfigSchema.optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const scan = await getScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(scan.userId, ctx.user);

        let config: IntegrationsConfig | undefined = input.integrations;
        if (!config) {
          const stored = await getIntegrationByUser(ctx.user.id);
          if (!stored?.configEnc) {
            throw new TRPCError({ code: "BAD_REQUEST", message: "No ticketing integrations configured. Save integrations first or pass integrations inline." });
          }
          config = decryptIntegrationsConfig(stored.configEnc);
        }
        if (!config) {
          throw new TRPCError({ code: "BAD_REQUEST", message: "Integrations config required" });
        }
        if (config.jira?.enabled) await assertSafeUrlInput(config.jira.baseUrl, ["https:"]);
        const target = await getTargetById(scan.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
        const findings = await getFindingsByScan(input.scanId);
        const results = await pushFindingsToTicketing(config, findings, target.url, input.dryRun);
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

    retestFinding: protectedProcedure
      .input(z.object({ findingId: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const finding = await getFindingById(input.findingId);
        if (!finding) throw new TRPCError({ code: "NOT_FOUND" });
        const scan = await getScanById(finding.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(scan.userId, ctx.user);
        const target = await getTargetById(scan.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND" });

        const tools = [finding.category.toLowerCase().includes("nuclei") ? "nuclei"
          : finding.category.toLowerCase().includes("zap") ? "zap"
          : finding.category.toLowerCase().includes("ssrf") ? "ssrf"
          : finding.category.toLowerCase().includes("sql") ? "sqli"
          : finding.category.toLowerCase().includes("xss") ? "xss"
          : finding.category.toLowerCase().includes("header") ? "headers"
          : finding.category.toLowerCase().includes("auth") ? "auth"
          : "headers"];

        const scanId = await createScan({
          targetId: target.id,
          userId: ctx.user.id,
          status: "queued",
          tools: tools.join(","),
          scanMode: "light",
          triggeredBy: "manual",
        });

        const storedAuth = (target.authConfig ?? undefined) as AuthScanConfig | undefined;
        setImmediate(() => {
          runScan(
            scanId,
            target.id,
            target.url,
            tools,
            "light",
            storedAuth,
            (target as Target & { manifestPath?: string | null }).manifestPath ?? undefined,
            storedAuth?.loginCredentials,
            target.repoUrl ?? undefined,
            (target as Target & { openapiUrl?: string | null }).openapiUrl ?? undefined
          ).catch(console.error);
        });

        return { success: true, scanId, retestedFindingId: finding.id };
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
          cronExpression: z.string().min(1).max(100),
          tools: toolList.default([...LIGHT_DEFAULT_TOOLS]),
          scanMode: z.enum(["light", "full"]).default("light"),
          autoPushTicketing: z.boolean().default(false),
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
          scanMode: input.scanMode,
          autoPushTicketing: input.autoPushTicketing,
          enabled: input.enabled,
        });
        return { success: true };
      }),

    update: protectedProcedure
      .input(
        z.object({
          id: z.number(),
          cronExpression: z.string().min(1).max(100).optional(),
          tools: toolList.optional(),
          scanMode: z.enum(["light", "full"]).optional(),
          autoPushTicketing: z.boolean().optional(),
          enabled: z.boolean().optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        const schedule = await getScheduleById(input.id);
        if (!schedule) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(schedule.userId, ctx.user);
        const { id, tools, ...rest } = input;
        const data: Record<string, unknown> = { ...rest };
        if (tools) data.tools = tools.join(",");
        await updateSchedule(id, data as any);
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const schedule = await getScheduleById(input.id);
        if (!schedule) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrAdmin(schedule.userId, ctx.user);
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
      .input(z.object({ days: z.number().int().min(1).max(365).default(30) }))
      .query(async ({ ctx, input }) => {
        return getScanTrends(ctx.user.id, ctx.user.role === "admin", input.days);
      }),

    recentScans: protectedProcedure.query(async ({ ctx }) => {
      if (ctx.user.role === "admin") return getAllScans(10);
      return getScansByUser(ctx.user.id, 10);
    }),
  }),

  // ─── Integrations ─────────────────────────────────────────────────────────
  integrations: router({
    get: protectedProcedure.query(async ({ ctx }) => {
      const row = await getIntegrationByUser(ctx.user.id);
      if (!row?.configEnc) return { configured: false, config: null as IntegrationsConfig | null };
      try {
        const config = redactIntegrationsConfig(decryptIntegrationsConfig(row.configEnc));
        return { configured: true, config };
      } catch {
        return { configured: false, config: null };
      }
    }),

    save: protectedProcedure
      .input(z.object({ config: integrationsConfigSchema }))
      .mutation(async ({ ctx, input }) => {
        if (input.config.jira?.enabled) await assertSafeUrlInput(input.config.jira.baseUrl, ["https:"]);
        // Merge secrets: if UI sent ******** keep previous secret
        const existing = await getIntegrationByUser(ctx.user.id);
        let merged = input.config as IntegrationsConfig;
        if (existing?.configEnc) {
          try {
            const prev = decryptIntegrationsConfig(existing.configEnc);
            if (merged.jira && merged.jira.apiToken === "********" && prev.jira) {
              merged = { ...merged, jira: { ...merged.jira, apiToken: prev.jira.apiToken } };
            }
            if (merged.github && merged.github.token === "********" && prev.github) {
              merged = { ...merged, github: { ...merged.github, token: prev.github.token } };
            }
            if (merged.linear && merged.linear.apiKey === "********" && prev.linear) {
              merged = { ...merged, linear: { ...merged.linear, apiKey: prev.linear.apiKey } };
            }
          } catch { /* ignore */ }
        }
        const enc = encryptIntegrationsConfig(merged);
        await upsertIntegration(ctx.user.id, enc);
        return { success: true };
      }),

    delete: protectedProcedure.mutation(async ({ ctx }) => {
      await deleteIntegration(ctx.user.id);
      return { success: true };
    }),
  }),

  // ─── CI/CD Pipeline ───────────────────────────────────────────────────────
  cicd: router({
    scan: publicProcedure
      .input(z.object({
        targetUrl: httpUrl,
        tools: toolList.default([...LIGHT_DEFAULT_TOOLS]),
        scanMode: z.enum(["light", "full"]).default("light"),
        /** Preferred alias */
        failOnSeverity: z.enum(["critical", "high", "medium", "low"]).optional(),
        /** Backward-compatible alias */
        failOn: z.enum(["critical", "high", "medium", "low"]).optional(),
        apiKey: z.string().min(1).max(512),
      }))
      .mutation(async ({ input }) => {
        const expectedKey = process.env.CICD_API_KEY;
        if (!expectedKey || !safeEqual(input.apiKey, expectedKey)) {
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid CI/CD API key" });
        }
        await assertSafeUrlInput(input.targetUrl);

        const ciUserId = 0;
        const ciTargetId = 0;
        const failThreshold = input.failOnSeverity ?? input.failOn ?? "high";

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
        const threshold = severityOrder[failThreshold] ?? 1;
        const failFindings = findings.filter((f) => (severityOrder[f.severity] ?? 4) <= threshold);
        const passed = failFindings.length === 0;
        const grade = (() => { const s = scan?.securityScore ?? 0; return s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 55 ? "D" : "F"; })();

        return {
          pass: passed,
          passed,
          exitCode: passed ? 0 : 1,
          scanId,
          targetUrl: input.targetUrl,
          securityScore: scan?.securityScore ?? 0,
          securityGrade: grade,
          riskLevel: scan?.riskLevel ?? "unknown",
          threshold: failThreshold,
          failOnSeverity: failThreshold,
          totalFindings: findings.length,
          failingFindings: failFindings.length,
          counts: {
            critical: findings.filter((f) => f.severity === "critical").length,
            high: findings.filter((f) => f.severity === "high").length,
            medium: findings.filter((f) => f.severity === "medium").length,
            low: findings.filter((f) => f.severity === "low").length,
            info: findings.filter((f) => f.severity === "info").length,
          },
          bySeverity: {
            critical: findings.filter((f) => f.severity === "critical").length,
            high: findings.filter((f) => f.severity === "high").length,
            medium: findings.filter((f) => f.severity === "medium").length,
            low: findings.filter((f) => f.severity === "low").length,
            info: findings.filter((f) => f.severity === "info").length,
          },
          findingIds: failFindings.map((f) => f.id),
          findings: findings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            cvssScore: f.cvssScore ? Number(f.cvssScore) : null,
            cweId: f.cweId,
            recommendation: f.recommendation,
          })),
          summary: `${passed ? "PASS" : "FAIL"} — ${findings.length} finding(s), ${failFindings.length} at or above ${failThreshold} severity. Score: ${scan?.securityScore ?? 0}/100 (Grade ${grade}).`,
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
      .input(z.object({ limit: listLimit.default(100) }))
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
