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
  createCicdApiKey,
  createFindingWaiver,
  createOrganization,
  deleteFindingWaiver,
  deleteIntegration,
  ensureUserOrg,
  getActiveWaiverFingerprints,
  getIntegrationByUser,
  getIntegrationForUser,
  getScansByOrg,
  getTargetByUrlAndOrg,
  getTargetsByOrg,
  listAuditEvents,
  listCicdApiKeys,
  listFindingWaivers,
  listOrganizations,
  listScanArtifacts,
  revokeCicdApiKey,
  setUserOrg,
  updateFindingStatus,
  updateSchedule,
  updateTarget,
  updateUserRole,
  upsertIntegration,
  validateCicdApiKey,
  writeAuditEvent,
  getOrganizationById,
  setUserOrgRole,
  listScanPolicies,
  getScanPolicyById,
  createScanPolicy,
  updateScanPolicy,
  deleteScanPolicy,
  getDefaultScanPolicy,
  getComplianceCoverage,
  getScanArtifactById,
  getTargetsByOrgAndEnv,
  getUsersByOrg,
} from "./db";
import { enqueueDurableScan, enqueueScanDetached, getScanQueueStats } from "./scanQueue";
import type { Scan, ScanFinding, Target } from "../drizzle/schema";
import { generateExecutiveSummary, generateJSONReport, generateMarkdownReport } from "./reportGenerator";
import { generateSarifReport } from "./sarif";
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
import { findingFingerprint } from "./findingFingerprint";
import { incCounter } from "./metrics";

const httpUrl = z.string().max(2048).url().refine(isHttpUrl, "URL must use http or https");
const httpsUrl = z.string().max(2048).url().refine(u => u.startsWith("https://") && isHttpUrl(u), "URL must use https");
const toolList = z.array(z.string().max(64)).max(64);

const authProfileSchema = z.object({
  name: z.string().max(255),
  type: z.enum(["none", "bearer", "basic", "cookie"]),
  token: z.string().max(8192).optional(),
  username: z.string().max(255).optional(),
  password: z.string().max(1024).optional(),
  cookie: z.string().max(8192).optional(),
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
  webhooks: z.array(z.object({
    url: httpsUrl,
    secret: z.string().max(512).optional(),
    type: z.enum(["slack", "teams", "generic"]).default("generic"),
    events: z.array(z.enum(["scan.completed", "scan.failed", "gate.failed", "finding.critical"])).optional(),
  })).max(10).optional(),
});

async function buildCicdStatusPayload(
  scanId: number,
  targetUrl: string,
  failThreshold: string,
  opts?: { onlyNew?: boolean; orgId?: number | null }
) {
  const scan = await getScanById(scanId);
  let findings = await getFindingsByScan(scanId);
  // Ignore resolved / false_positive for gate decisions
  findings = findings.filter((f) => f.status === "open" || f.status === "acknowledged");

  // Apply org waivers
  const orgId = opts?.orgId ?? scan?.orgId ?? null;
  if (orgId) {
    const waived = (await getActiveWaiverFingerprints(orgId)) || new Set<string>();
    findings = findings.filter((f) => !waived.has(findingFingerprint(f)));
  }

  // Fail-on-new: only findings listed in trendSummary.newItems
  if (opts?.onlyNew) {
    const trend = scan?.trendSummary as { newItems?: string[] } | null;
    const newTitles = new Set((trend?.newItems || []).map((t) => t.toLowerCase()));
    if (newTitles.size > 0) {
      findings = findings.filter((f) => newTitles.has(f.title.toLowerCase()));
    } else if (scan?.status === "completed") {
      // First scan / no baseline → treat all as new (keep findings)
    }
  }

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const threshold = severityOrder[failThreshold] ?? 1;
  const failFindings = findings.filter((f) => (severityOrder[f.severity] ?? 4) <= threshold);
  const passed = scan?.status === "failed" ? false : failFindings.length === 0;
  const grade = (() => {
    const s = scan?.securityScore ?? 0;
    return s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 55 ? "D" : "F";
  })();
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
  return {
    scanId,
    status: scan?.status ?? "unknown",
    pass: passed,
    passed,
    exitCode: passed ? 0 : 1,
    targetUrl,
    securityScore: scan?.securityScore ?? 0,
    securityGrade: grade,
    riskLevel: scan?.riskLevel ?? "unknown",
    threshold: failThreshold,
    failOnSeverity: failThreshold,
    onlyNew: !!opts?.onlyNew,
    totalFindings: findings.length,
    failingFindings: failFindings.length,
    counts,
    bySeverity: counts,
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
    summary: `${passed ? "PASS" : "FAIL"} — ${findings.length} finding(s), ${failFindings.length} at or above ${failThreshold}. Score: ${scan?.securityScore ?? 0}/100 (Grade ${grade}).`,
  };
}
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
    orgId: null,
    parentFindingId: null,
    scenarios: null,
    trendSummary: null,
    createdAt: new Date(),
  };
  const mockTarget: Target = {
    id: 0,
    userId: 0,
    orgId: null,
    name: "Demo Application",
    url: "https://demo.example.com",
    repoUrl: null,
    description: "Sample target for demo report",
    tags: null,
    scanFrequency: "manual",
    isActive: true,
    authConfig: null,
    openapiUrl: null,
    manifestPath: null,
    environment: "production",
    policyId: null,
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
      confidence: null,
      templateId: null,
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

function assertOwnerOrgOrAdmin(
  resource: { userId: number; orgId?: number | null },
  ctxUser: { id: number; role: string; orgId?: number | null }
) {
  if (ctxUser.role === "admin") return;
  if (resource.userId === ctxUser.id) return;
  if (resource.orgId && ctxUser.orgId && resource.orgId === ctxUser.orgId) return;
  throw new TRPCError({ code: "FORBIDDEN", message: "Access denied" });
}

function assertCanWrite(ctxUser: { role: string; orgRole?: string | null }) {
  if (ctxUser.role === "admin") return;
  const orgRole = ctxUser.orgRole || "member";
  if (orgRole === "viewer" || orgRole === "auditor") {
    throw new TRPCError({ code: "FORBIDDEN", message: "Read-only org role" });
  }
}

function assertOrgAdmin(ctxUser: { role: string; orgRole?: string | null }) {
  if (ctxUser.role === "admin") return;
  if (ctxUser.orgRole === "org_admin") return;
  throw new TRPCError({ code: "FORBIDDEN", message: "Org admin required" });
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
      const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
      if (orgId) return getTargetsByOrg(orgId);
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
          environment: z.enum(["development", "staging", "production"]).or(z.string().max(64)).default("production"),
          policyId: z.number().optional().nullable(),
          openapiUrl: httpUrl.optional().or(z.literal("")),
          manifestPath: z.string().max(500).optional().or(z.literal("")),
          authConfig: authConfigSchema.optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        assertCanWrite(ctx.user);
        await assertSafeUrlInput(input.url);
        if (input.repoUrl) await assertSafeUrlInput(input.repoUrl, ["https:"]);
        if (input.openapiUrl) await assertSafeUrlInput(input.openapiUrl);
        if (input.authConfig?.loginCredentials) await assertSafeUrlInput(input.authConfig.loginCredentials.loginUrl);
        const { openapiUrl, manifestPath, authConfig, ...rest } = input;
        const orgId = await ensureUserOrg(ctx.user.id);
        await createTarget({
          ...rest,
          userId: ctx.user.id,
          orgId: orgId ?? null,
          openapiUrl: openapiUrl || null,
          manifestPath: manifestPath || null,
          authConfig: authConfig ?? null,
          environment: input.environment || "production",
          policyId: input.policyId ?? null,
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
          environment: z.enum(["development", "staging", "production"]).or(z.string().max(64)).optional(),
          policyId: z.number().nullable().optional(),
          openapiUrl: httpUrl.optional().or(z.literal("")).or(z.null()),
          manifestPath: z.string().max(500).optional().or(z.literal("")).or(z.null()),
          authConfig: authConfigSchema.nullable().optional(),
        })
      )
      .mutation(async ({ ctx, input }) => {
        assertCanWrite(ctx.user);
        const { id, ...data } = input;
        const target = await getTargetById(id);
        if (!target) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrgOrAdmin(target, ctx.user);
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
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (orgId) return getScansByOrg(orgId, input.limit);
        return getScansByUser(ctx.user.id, input.limit);
      }),

    get: protectedProcedure.input(z.object({ id: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.id);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrgOrAdmin(scan, ctx.user);
      return scan;
    }),

    artifacts: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrgOrAdmin(scan, ctx.user);
      return listScanArtifacts(input.scanId);
    }),

    artifactContent: protectedProcedure
      .input(z.object({ artifactId: z.number() }))
      .query(async ({ ctx, input }) => {
        const art = await getScanArtifactById(input.artifactId);
        if (!art) throw new TRPCError({ code: "NOT_FOUND" });
        const scan = await getScanById(art.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrgOrAdmin(scan, ctx.user);
        const { readArtifact } = await import("./artifactStore");
        const buf = await readArtifact(art.storageKey);
        if (!buf) throw new TRPCError({ code: "NOT_FOUND", message: "Artifact file missing" });
        const text = buf.toString("utf8");
        // Avoid huge payloads over tRPC
        const truncated = text.length > 500_000;
        return {
          id: art.id,
          tool: art.tool,
          contentType: art.contentType,
          storageKey: art.storageKey,
          sizeBytes: art.sizeBytes,
          truncated,
          content: truncated ? text.slice(0, 500_000) : text,
        };
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

        const orgId = target.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (orgId) {
          const { updateScan } = await import("./db");
          await updateScan(scanId, { orgId });
        }

        enqueueDurableScan({
          scanId,
          targetId: target.id,
          targetUrl: target.url,
          tools: input.tools,
          scanMode: input.scanMode,
          authConfig,
          manifestPath: manifestPath ?? undefined,
          loginCredentials: loginCreds,
          repoUrl: target.repoUrl ?? undefined,
          openapiUrl: openapiUrl ?? undefined,
          userId: ctx.user.id,
        });

        return { scanId, success: true, queue: getScanQueueStats() };
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
          triggeredBy: "retest",
          parentFindingId: finding.id,
          orgId: target.orgId ?? null,
        });

        const storedAuth = (target.authConfig ?? undefined) as AuthScanConfig | undefined;
        enqueueDurableScan({
          scanId,
          targetId: target.id,
          targetUrl: target.url,
          tools,
          scanMode: "light",
          authConfig: storedAuth,
          manifestPath: (target as Target & { manifestPath?: string | null }).manifestPath ?? undefined,
          loginCredentials: storedAuth?.loginCredentials,
          repoUrl: target.repoUrl ?? undefined,
          openapiUrl: (target as Target & { openapiUrl?: string | null }).openapiUrl ?? undefined,
          userId: ctx.user.id,
        });

        return { success: true, scanId, retestedFindingId: finding.id, parentFindingId: finding.id };
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

    getSARIF: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ ctx, input }) => {
      const scan = await getScanById(input.scanId);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
      assertOwnerOrgOrAdmin(scan, ctx.user);
      const target = await getTargetById(scan.targetId);
      if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
      const findings = await getFindingsByScan(input.scanId);
      const report = await getReportByScan(input.scanId);
      const reportData = {
        scan,
        target,
        findings,
        generatedAt: report?.generatedAt ?? new Date(),
      };
      return { sarif: generateSarifReport(reportData), title: report?.title ?? `Scan ${scan.id} SARIF` };
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
      const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
      const row = await getIntegrationForUser(ctx.user.id, orgId);
      if (!row?.configEnc) return { configured: false, config: null as IntegrationsConfig | null, orgScoped: false };
      try {
        const config = redactIntegrationsConfig(decryptIntegrationsConfig(row.configEnc));
        return { configured: true, config, orgScoped: !!row.orgId };
      } catch {
        return { configured: false, config: null, orgScoped: false };
      }
    }),

    save: protectedProcedure
      .input(z.object({ config: integrationsConfigSchema }))
      .mutation(async ({ ctx, input }) => {
        if (input.config.jira?.enabled) await assertSafeUrlInput(input.config.jira.baseUrl, ["https:"]);
        for (const wh of input.config.webhooks || []) {
          await assertSafeUrlInput(wh.url, ["https:"]);
        }
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        const existing = await getIntegrationForUser(ctx.user.id, orgId);
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
            if (merged.webhooks) {
              merged = {
                ...merged,
                webhooks: merged.webhooks.map((w, i) =>
                  w.secret === "********" && prev.webhooks?.[i]?.secret
                    ? { ...w, secret: prev.webhooks[i].secret }
                    : w
                ),
              };
            }
          } catch { /* ignore */ }
        }
        const enc = encryptIntegrationsConfig(merged);
        await upsertIntegration(ctx.user.id, enc, orgId);
        await writeAuditEvent({
          orgId,
          userId: ctx.user.id,
          action: "integrations.save",
          resourceType: "integrations",
          resourceId: String(ctx.user.id),
        });
        return { success: true };
      }),

    delete: protectedProcedure.mutation(async ({ ctx }) => {
      await deleteIntegration(ctx.user.id);
      return { success: true };
    }),
  }),

  // ─── Finding waivers ──────────────────────────────────────────────────────
  waivers: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
      if (!orgId) return [];
      return listFindingWaivers(orgId);
    }),
    create: protectedProcedure
      .input(z.object({
        title: z.string().min(1).max(500),
        category: z.string().max(100).optional(),
        cweId: z.string().max(20).optional(),
        reason: z.string().max(2000).optional(),
        expiresAt: z.string().datetime().optional(),
        findingId: z.number().optional(),
      }))
      .mutation(async ({ ctx, input }) => {
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (!orgId) throw new TRPCError({ code: "BAD_REQUEST", message: "No organization" });
        let title = input.title;
        let category = input.category;
        let cweId = input.cweId;
        if (input.findingId) {
          const finding = await getFindingById(input.findingId);
          if (!finding) throw new TRPCError({ code: "NOT_FOUND" });
          const scan = await getScanById(finding.scanId);
          if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
          assertOwnerOrgOrAdmin(scan, ctx.user);
          title = finding.title;
          category = finding.category;
          cweId = finding.cweId || undefined;
          await updateFindingStatus(finding.id, "false_positive");
        }
        const id = await createFindingWaiver({
          orgId,
          userId: ctx.user.id,
          fingerprint: findingFingerprint({ title, category, cweId }),
          title,
          category: category ?? null,
          cweId: cweId ?? null,
          reason: input.reason ?? null,
          expiresAt: input.expiresAt ? new Date(input.expiresAt) : null,
        });
        await writeAuditEvent({
          orgId,
          userId: ctx.user.id,
          action: "waiver.create",
          resourceType: "waiver",
          resourceId: String(id),
          meta: { title },
        });
        return { success: true, id };
      }),
    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (!orgId) throw new TRPCError({ code: "BAD_REQUEST", message: "No organization" });
        await deleteFindingWaiver(input.id, orgId);
        await writeAuditEvent({
          orgId,
          userId: ctx.user.id,
          action: "waiver.delete",
          resourceType: "waiver",
          resourceId: String(input.id),
        });
        return { success: true };
      }),
  }),

  // ─── Organizations ────────────────────────────────────────────────────────
  orgs: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      if (ctx.user.role === "admin") return listOrganizations();
      const orgId = await ensureUserOrg(ctx.user.id);
      if (!orgId) return [];
      const all = await listOrganizations();
      return all.filter((o) => o.id === orgId);
    }),
    mine: protectedProcedure.query(async ({ ctx }) => {
      const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
      if (!orgId) return null;
      return (await getOrganizationById(orgId)) ?? null;
    }),
    create: adminProcedure
      .input(z.object({ name: z.string().min(1).max(255), slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/) }))
      .mutation(async ({ ctx, input }) => {
        const id = await createOrganization(input.name, input.slug);
        await writeAuditEvent({
          orgId: id,
          userId: ctx.user.id,
          action: "org.create",
          resourceType: "organization",
          resourceId: String(id),
          meta: { name: input.name, slug: input.slug },
        });
        return { success: true, id };
      }),
    assignUser: adminProcedure
      .input(z.object({
        userId: z.number(),
        orgId: z.number(),
        orgRole: z.enum(["org_admin", "member", "viewer", "auditor"]).default("member"),
      }))
      .mutation(async ({ ctx, input }) => {
        await setUserOrgRole(input.userId, input.orgId, input.orgRole);
        await writeAuditEvent({
          orgId: input.orgId,
          userId: ctx.user.id,
          action: "org.assignUser",
          resourceType: "user",
          resourceId: String(input.userId),
          meta: { orgId: input.orgId, orgRole: input.orgRole },
        });
        return { success: true };
      }),
    audit: protectedProcedure
      .input(z.object({ limit: listLimit.default(50) }))
      .query(async ({ ctx, input }) => {
        if (ctx.user.role === "admin") return listAuditEvents(null, input.limit);
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (!orgId) return [];
        return listAuditEvents(orgId, input.limit);
      }),
  }),

  // ─── CI/CD Pipeline ───────────────────────────────────────────────────────
  cicd: router({
    createKey: protectedProcedure
      .input(z.object({ name: z.string().min(1).max(255).default("CI key") }))
      .mutation(async ({ ctx, input }) => {
        const orgId = await ensureUserOrg(ctx.user.id);
        const created = await createCicdApiKey(ctx.user.id, input.name, orgId);
        return { ...created, note: "Copy this API key now — it will not be shown again." };
      }),

    listKeys: protectedProcedure.query(async ({ ctx }) => {
      return listCicdApiKeys(ctx.user.id, ctx.user.role === "admin");
    }),

    revokeKey: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const ok = await revokeCicdApiKey(input.id, ctx.user.id, ctx.user.role === "admin");
        if (!ok) throw new TRPCError({ code: "NOT_FOUND" });
        return { success: true };
      }),

    /** Async start — returns scanId immediately; poll with cicd.status */
    scan: publicProcedure
      .input(z.object({
        targetUrl: httpUrl.optional(),
        targetId: z.number().optional(),
        environment: z.string().max(64).optional(),
        policyId: z.number().optional(),
        tools: toolList.default([...LIGHT_DEFAULT_TOOLS]),
        scanMode: z.enum(["light", "full"]).default("light"),
        failOnSeverity: z.enum(["critical", "high", "medium", "low"]).optional(),
        failOn: z.enum(["critical", "high", "medium", "low"]).optional(),
        /** When true, only new (regression) findings fail the gate */
        onlyNew: z.boolean().default(false),
        apiKey: z.string().min(1).max(512),
        /** When true, wait for completion (legacy sync behavior, still queued) */
        wait: z.boolean().default(false),
      }))
      .mutation(async ({ input }) => {
        const auth = await validateCicdApiKey(input.apiKey);
        if (!auth.ok) throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid CI/CD API key" });
        incCounter("ghoststrike_cicd_scans_total");

        let target = input.targetId ? await getTargetById(input.targetId) : undefined;
        if (input.targetId && !target) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
        if (target) {
          if (auth.orgId && target.orgId && target.orgId !== auth.orgId) {
            throw new TRPCError({ code: "FORBIDDEN", message: "Target not in API key org" });
          }
          if (auth.userId !== 0 && !auth.orgId && target.userId !== auth.userId) {
            throw new TRPCError({ code: "FORBIDDEN", message: "Target access denied" });
          }
        }

        // Resolve by environment within org when no targetId/url
        if (!target && auth.orgId && input.environment && !input.targetUrl) {
          const envTargets = await getTargetsByOrgAndEnv(auth.orgId, input.environment);
          target = envTargets[0];
        }

        const targetUrl = target?.url || input.targetUrl;
        if (!targetUrl) throw new TRPCError({ code: "BAD_REQUEST", message: "targetUrl, targetId, or environment required" });
        await assertSafeUrlInput(targetUrl);

        // Auto-bind by URL within org when targetId omitted
        if (!target && auth.orgId) {
          target = await getTargetByUrlAndOrg(targetUrl, auth.orgId);
        }

        // Apply org policy defaults
        let tools = input.tools;
        let scanMode = input.scanMode;
        let failThreshold = input.failOnSeverity ?? input.failOn ?? "high";
        let onlyNew = input.onlyNew;
        const policyId = input.policyId ?? target?.policyId ?? null;
        if (policyId) {
          const policy = await getScanPolicyById(policyId);
          if (policy && (!auth.orgId || policy.orgId === auth.orgId || !auth.orgId)) {
            if (!input.tools?.length || input.tools.join(",") === LIGHT_DEFAULT_TOOLS.join(",")) {
              tools = policy.tools.split(",").map((t) => t.trim()).filter(Boolean);
            }
            if (!input.scanMode || input.scanMode === "light") scanMode = policy.scanMode as "light" | "full";
            if (!input.failOnSeverity && !input.failOn) failThreshold = policy.failOnSeverity as any;
            if (input.onlyNew === false && policy.onlyNew) onlyNew = true;
            if (!input.onlyNew) onlyNew = !!policy.onlyNew;
          }
        } else if (auth.orgId) {
          const def = await getDefaultScanPolicy(auth.orgId);
          if (def && !input.failOnSeverity && !input.failOn) {
            failThreshold = def.failOnSeverity as any;
            onlyNew = input.onlyNew || !!def.onlyNew;
          }
        }

        const boundTargetId = target?.id ?? 0;
        const authConfig = target?.authConfig as AuthScanConfig | null | undefined;
        const scanId = await createScan({
          targetId: boundTargetId,
          userId: auth.userId || target?.userId || 0,
          tools: tools.join(","),
          scanMode,
          triggeredBy: "cicd",
          orgId: auth.orgId ?? target?.orgId ?? null,
          status: "queued",
        });

        await writeAuditEvent({
          orgId: auth.orgId ?? target?.orgId ?? null,
          userId: auth.userId || null,
          action: "cicd.scan",
          resourceType: "scan",
          resourceId: String(scanId),
          meta: { targetId: boundTargetId, targetUrl, onlyNew, policyId },
        });

        const payload = {
          scanId,
          targetId: boundTargetId,
          targetUrl,
          tools,
          scanMode,
          authConfig: authConfig || undefined,
          manifestPath: target?.manifestPath || undefined,
          loginCredentials: authConfig?.loginCredentials,
          repoUrl: target?.repoUrl || undefined,
          openapiUrl: target?.openapiUrl || undefined,
          userId: auth.userId || target?.userId || 0,
        };

        const gateOpts = { onlyNew, orgId: auth.orgId ?? target?.orgId ?? null };

        if (input.wait) {
          const { enqueueScan, enqueueDurableScan: _ed } = await import("./scanQueue");
          const { runScan: rs } = await import("./scanEngine");
          await enqueueScan(async () => {
            await rs(
              payload.scanId,
              payload.targetId,
              payload.targetUrl,
              payload.tools,
              payload.scanMode as any,
              payload.authConfig as any,
              payload.manifestPath || undefined,
              payload.loginCredentials as any,
              payload.repoUrl || undefined,
              payload.openapiUrl || undefined
            );
          }, scanId, payload);
          return buildCicdStatusPayload(scanId, targetUrl, failThreshold, gateOpts);
        }

        const { enqueueDurableScan } = await import("./scanQueue");
        enqueueDurableScan(payload);
        return {
          scanId,
          targetId: boundTargetId || null,
          status: "queued" as const,
          failOnSeverity: failThreshold,
          onlyNew,
          queue: getScanQueueStats(),
          message: "Scan queued. Poll cicd.status until status is completed or failed.",
        };
      }),

    status: publicProcedure
      .input(z.object({
        scanId: z.number(),
        apiKey: z.string().min(1).max(512),
        failOnSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),
        onlyNew: z.boolean().default(false),
      }))
      .query(async ({ input }) => {
        const auth = await validateCicdApiKey(input.apiKey);
        if (!auth.ok) throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid CI/CD API key" });
        const scan = await getScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        if (auth.userId !== 0 && scan.userId !== auth.userId && auth.userId !== 0) {
          if (scan.userId !== auth.userId) throw new TRPCError({ code: "FORBIDDEN" });
        }
        if (scan.status !== "completed" && scan.status !== "failed") {
          return {
            scanId: scan.id,
            status: scan.status,
            queue: getScanQueueStats(),
            pass: null,
            passed: null,
            exitCode: null,
          };
        }
        const payload = await buildCicdStatusPayload(
          scan.id,
          "(stored)",
          input.failOnSeverity,
          { onlyNew: input.onlyNew, orgId: auth.orgId ?? scan.orgId }
        );
        if (!payload.passed) incCounter("ghoststrike_cicd_gate_failures_total");
        else incCounter("ghoststrike_cicd_gate_passes_total");
        return payload;
      }),

    /** Fetch SARIF for Code Scanning upload (CI key auth) */
    sarif: publicProcedure
      .input(z.object({
        scanId: z.number(),
        apiKey: z.string().min(1).max(512),
      }))
      .query(async ({ input }) => {
        const auth = await validateCicdApiKey(input.apiKey);
        if (!auth.ok) throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid CI/CD API key" });
        const scan = await getScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        if (auth.userId !== 0 && scan.userId !== auth.userId) {
          throw new TRPCError({ code: "FORBIDDEN" });
        }
        const target = await getTargetById(scan.targetId);
        if (!target && scan.targetId !== 0) throw new TRPCError({ code: "NOT_FOUND", message: "Target not found" });
        const findings = await getFindingsByScan(input.scanId);
        const fakeTarget = target || {
          id: 0,
          name: "CI target",
          url: "https://example.invalid",
        } as any;
        return {
          sarif: generateSarifReport({
            scan,
            target: fakeTarget,
            findings,
            generatedAt: new Date(),
          }),
        };
      }),
  }),

  // ─── Scan policies ────────────────────────────────────────────────────────
  policies: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
      if (!orgId) return [];
      return listScanPolicies(orgId);
    }),
    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1).max(255),
        description: z.string().max(2000).optional(),
        tools: toolList,
        scanMode: z.enum(["light", "full"]).default("light"),
        failOnSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),
        onlyNew: z.boolean().default(true),
        isDefault: z.boolean().default(false),
      }))
      .mutation(async ({ ctx, input }) => {
        assertCanWrite(ctx.user);
        assertOrgAdmin(ctx.user);
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (!orgId) throw new TRPCError({ code: "BAD_REQUEST", message: "No organization" });
        const id = await createScanPolicy({
          orgId,
          name: input.name,
          description: input.description ?? null,
          tools: input.tools.join(","),
          scanMode: input.scanMode,
          failOnSeverity: input.failOnSeverity,
          onlyNew: input.onlyNew,
          isDefault: input.isDefault,
        });
        await writeAuditEvent({
          orgId, userId: ctx.user.id, action: "policy.create",
          resourceType: "policy", resourceId: String(id),
        });
        return { success: true, id };
      }),
    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string().min(1).max(255).optional(),
        description: z.string().max(2000).optional().nullable(),
        tools: toolList.optional(),
        scanMode: z.enum(["light", "full"]).optional(),
        failOnSeverity: z.enum(["critical", "high", "medium", "low"]).optional(),
        onlyNew: z.boolean().optional(),
        isDefault: z.boolean().optional(),
      }))
      .mutation(async ({ ctx, input }) => {
        assertOrgAdmin(ctx.user);
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (!orgId) throw new TRPCError({ code: "BAD_REQUEST" });
        const { id, tools, ...rest } = input;
        await updateScanPolicy(id, orgId, {
          ...rest,
          ...(tools ? { tools: tools.join(",") } : {}),
        });
        return { success: true };
      }),
    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ ctx, input }) => {
        assertOrgAdmin(ctx.user);
        const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
        if (!orgId) throw new TRPCError({ code: "BAD_REQUEST" });
        await deleteScanPolicy(input.id, orgId);
        return { success: true };
      }),
  }),

  // ─── Compliance coverage ──────────────────────────────────────────────────
  compliance: router({
    coverage: protectedProcedure.query(async ({ ctx }) => {
      const orgId = ctx.user.orgId ?? (await ensureUserOrg(ctx.user.id));
      return getComplianceCoverage(orgId, ctx.user.role === "admin");
    }),
  }),

  // ─── AI triage + SBOM ──────────────────────────────────────────────────────
  insights: router({
    triage: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ ctx, input }) => {
        const scan = await getScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrgOrAdmin(scan, ctx.user);
        const findings = await getFindingsByScan(input.scanId);
        const { triageFindings } = await import("./aiTriage");
        return triageFindings(findings.map((f) => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          category: f.category,
          description: f.description,
          cweId: f.cweId,
        })));
      }),
    sbom: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ ctx, input }) => {
        const scan = await getScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND" });
        assertOwnerOrgOrAdmin(scan, ctx.user);
        const target = await getTargetById(scan.targetId);
        const findings = await getFindingsByScan(input.scanId);
        const { buildCycloneDxSbom, componentsFromScaFindings } = await import("./sbom");
        const { components, vulnerabilities } = componentsFromScaFindings(findings);
        return buildCycloneDxSbom({
          targetName: target?.name || `target-${scan.targetId}`,
          targetUrl: target?.url || "",
          scanId: scan.id,
          components,
          vulnerabilities,
        });
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

    setOrgRole: adminProcedure
      .input(z.object({
        userId: z.number(),
        orgId: z.number(),
        orgRole: z.enum(["org_admin", "member", "viewer", "auditor"]),
      }))
      .mutation(async ({ ctx, input }) => {
        await setUserOrgRole(input.userId, input.orgId, input.orgRole);
        await writeAuditEvent({
          orgId: input.orgId,
          userId: ctx.user.id,
          action: "org.setRole",
          resourceType: "user",
          resourceId: String(input.userId),
          meta: { orgRole: input.orgRole },
        });
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

    scanQueueStats: adminProcedure.query(async () => {
      return getScanQueueStats();
    }),

    orgMembers: adminProcedure
      .input(z.object({ orgId: z.number() }))
      .query(async ({ input }) => getUsersByOrg(input.orgId)),
  }),
});

export type AppRouter = typeof appRouter;
