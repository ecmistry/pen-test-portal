import { and, desc, eq, gte, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  InsertAuditEvent,
  InsertCicdApiKey,
  InsertFindingWaiver,
  InsertIntegration,
  InsertOrganization,
  InsertReport,
  InsertScan,
  InsertScanArtifact,
  InsertScanFinding,
  InsertScanJob,
  InsertScanLog,
  InsertSchedule,
  InsertTarget,
  InsertUser,
  InsertScanPolicy,
  auditEvents,
  cicdApiKeys,
  findingWaivers,
  integrations,
  organizations,
  reports,
  scanArtifacts,
  scanFindings,
  scanJobs,
  scanLogs,
  scanPolicies,
  scans,
  schedules,
  targets,
  users,
} from "../drizzle/schema";
import { ENV } from "./_core/env";
import { createHash, randomBytes } from "crypto";
import { findingFingerprint } from "./findingFingerprint";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
      await applyLightMigrations(_db);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

async function applyLightMigrations(db: ReturnType<typeof drizzle>) {
  const safeAlter = async (statement: string) => {
    try { await db.execute(sql.raw(statement)); } catch { /* column likely exists */ }
  };
  await safeAlter("ALTER TABLE scans ADD COLUMN authMode VARCHAR(20) DEFAULT NULL");
  await safeAlter("ALTER TABLE scans ADD COLUMN authMeta JSON DEFAULT NULL");
  await safeAlter("ALTER TABLE scan_findings ADD COLUMN authContext VARCHAR(20) DEFAULT NULL");
  await safeAlter("ALTER TABLE scan_findings ADD COLUMN affectedUrl TEXT DEFAULT NULL");
  await safeAlter("ALTER TABLE scan_findings ADD COLUMN affectedComponent VARCHAR(200) DEFAULT NULL");
  await safeAlter("ALTER TABLE scan_findings ADD COLUMN sourceFile VARCHAR(500) DEFAULT NULL");
  await safeAlter("ALTER TABLE scan_findings ADD COLUMN sourceLine INT DEFAULT NULL");
  await safeAlter("ALTER TABLE scan_findings ADD COLUMN sourceSnippet TEXT DEFAULT NULL");
  await safeAlter("ALTER TABLE targets ADD COLUMN repoUrl VARCHAR(2048) DEFAULT NULL");
  await safeAlter("ALTER TABLE targets ADD COLUMN authConfig JSON DEFAULT NULL");
  await safeAlter("ALTER TABLE targets ADD COLUMN openapiUrl VARCHAR(2048) DEFAULT NULL");
  await safeAlter("ALTER TABLE targets ADD COLUMN manifestPath VARCHAR(500) DEFAULT NULL");
  await safeAlter("ALTER TABLE schedules ADD COLUMN scanMode VARCHAR(20) DEFAULT 'light' NOT NULL");
  await safeAlter("ALTER TABLE schedules ADD COLUMN autoPushTicketing BOOLEAN DEFAULT FALSE NOT NULL");
  await safeAlter("ALTER TABLE users ADD COLUMN orgId INT DEFAULT NULL");
  await safeAlter("ALTER TABLE targets ADD COLUMN orgId INT DEFAULT NULL");
  await safeAlter("ALTER TABLE scans ADD COLUMN orgId INT DEFAULT NULL");
  await safeAlter("ALTER TABLE scans ADD COLUMN parentFindingId INT DEFAULT NULL");
  try {
    await db.execute(sql.raw(
      "ALTER TABLE scans MODIFY COLUMN triggeredBy ENUM('manual','schedule','cicd','retest') NOT NULL DEFAULT 'manual'"
    ));
  } catch { /* enum may already include values */ }
  await safeAlter("ALTER TABLE reports MODIFY markdownContent MEDIUMTEXT");
  await safeAlter("ALTER TABLE reports MODIFY executiveSummary MEDIUMTEXT");
  await safeAlter("ALTER TABLE reports MODIFY complianceNotes MEDIUMTEXT");
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS integrations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userId INT NOT NULL UNIQUE,
        configEnc TEXT NOT NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `));
  } catch { /* table may exist */ }
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS organizations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(100) NOT NULL UNIQUE,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `));
  } catch { /* exists */ }
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS cicd_api_keys (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userId INT NOT NULL,
        orgId INT NULL,
        name VARCHAR(255) NOT NULL,
        keyPrefix VARCHAR(16) NOT NULL,
        keyHash VARCHAR(128) NOT NULL,
        lastUsedAt TIMESTAMP NULL,
        revokedAt TIMESTAMP NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `));
  } catch { /* exists */ }
  await safeAlter("ALTER TABLE integrations ADD COLUMN orgId INT DEFAULT NULL");
  await safeAlter("ALTER TABLE users ADD COLUMN orgRole ENUM('org_admin','member','viewer','auditor') DEFAULT 'member'");
  await safeAlter("ALTER TABLE targets ADD COLUMN environment VARCHAR(64) DEFAULT 'production'");
  await safeAlter("ALTER TABLE targets ADD COLUMN policyId INT DEFAULT NULL");
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS scan_policies (
        id INT AUTO_INCREMENT PRIMARY KEY,
        orgId INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        description TEXT NULL,
        tools VARCHAR(500) NOT NULL,
        scanMode VARCHAR(20) NOT NULL DEFAULT 'light',
        failOnSeverity VARCHAR(20) NOT NULL DEFAULT 'high',
        onlyNew BOOLEAN NOT NULL DEFAULT TRUE,
        isDefault BOOLEAN NOT NULL DEFAULT FALSE,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_policies_org (orgId)
      )
    `));
  } catch { /* exists */ }
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS finding_waivers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        orgId INT NOT NULL,
        userId INT NOT NULL,
        fingerprint VARCHAR(255) NOT NULL,
        title VARCHAR(500) NOT NULL,
        category VARCHAR(100) NULL,
        cweId VARCHAR(20) NULL,
        reason TEXT NULL,
        expiresAt TIMESTAMP NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_waiver_org_fp (orgId, fingerprint)
      )
    `));
  } catch { /* exists */ }
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS audit_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        orgId INT NULL,
        userId INT NULL,
        action VARCHAR(100) NOT NULL,
        resourceType VARCHAR(64) NULL,
        resourceId VARCHAR(64) NULL,
        meta JSON NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_audit_org_created (orgId, createdAt)
      )
    `));
  } catch { /* exists */ }
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS scan_jobs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scanId INT NOT NULL,
        status ENUM('queued','running','completed','failed') NOT NULL DEFAULT 'queued',
        payload JSON NULL,
        errorMessage TEXT NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        startedAt TIMESTAMP NULL,
        completedAt TIMESTAMP NULL,
        INDEX idx_scan_jobs_status (status)
      )
    `));
  } catch { /* exists */ }
  try {
    await db.execute(sql.raw(`
      CREATE TABLE IF NOT EXISTS scan_artifacts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scanId INT NOT NULL,
        tool VARCHAR(64) NOT NULL,
        contentType VARCHAR(128) NOT NULL DEFAULT 'application/json',
        storageKey VARCHAR(512) NOT NULL,
        sizeBytes INT DEFAULT 0,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_artifacts_scan (scanId)
      )
    `));
  } catch { /* exists */ }

  // Ensure a default organization exists and backfill users/targets without orgId
  try {
    const existing = await db.select().from(organizations).limit(1);
    let orgId = existing[0]?.id;
    if (!orgId) {
      const ins = await db.insert(organizations).values({ name: "Default", slug: "default" } satisfies InsertOrganization);
      orgId = (ins as any)[0]?.insertId as number;
    }
    if (orgId) {
      await db.execute(sql.raw(`UPDATE users SET orgId = ${orgId} WHERE orgId IS NULL`));
      await db.execute(sql.raw(`UPDATE targets SET orgId = ${orgId} WHERE orgId IS NULL`));
      await db.execute(sql.raw(`UPDATE scans SET orgId = ${orgId} WHERE orgId IS NULL`));
    }
  } catch { /* best-effort backfill */ }
}

// ─── Users ────────────────────────────────────────────────────────────────────
export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  if (!db) return;

  const values: InsertUser = { openId: user.openId };
  const updateSet: Record<string, unknown> = {};
  const textFields = ["name", "email", "loginMethod"] as const;
  for (const field of textFields) {
    const value = user[field];
    if (value === undefined) continue;
    const normalized = value ?? null;
    values[field] = normalized;
    updateSet[field] = normalized;
  }
  if (user.lastSignedIn !== undefined) {
    values.lastSignedIn = user.lastSignedIn;
    updateSet.lastSignedIn = user.lastSignedIn;
  }
  if (user.role !== undefined) {
    values.role = user.role;
    updateSet.role = user.role;
  } else if (user.openId === ENV.ownerOpenId) {
    values.role = "admin";
    updateSet.role = "admin";
  }
  if (!values.lastSignedIn) values.lastSignedIn = new Date();
  if (Object.keys(updateSet).length === 0) updateSet.lastSignedIn = new Date();

  await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result[0];
}

export async function getAllUsers() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(users).orderBy(desc(users.createdAt));
}

export async function updateUserRole(userId: number, role: "user" | "admin") {
  const db = await getDb();
  if (!db) return;
  await db.update(users).set({ role }).where(eq(users.id, userId));
}

// ─── Targets ──────────────────────────────────────────────────────────────────
export async function getTargetsByUser(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(targets).where(eq(targets.userId, userId)).orderBy(desc(targets.createdAt));
}

export async function getAllTargets() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(targets).orderBy(desc(targets.createdAt));
}

export async function getTargetById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(targets).where(eq(targets.id, id)).limit(1);
  return result[0];
}

export async function createTarget(data: InsertTarget) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const result = await db.insert(targets).values(data);
  return result[0];
}

export async function updateTarget(id: number, data: Partial<InsertTarget>) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.update(targets).set(data).where(eq(targets.id, id));
}

export async function deleteTarget(id: number) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.delete(targets).where(eq(targets.id, id));
}

// ─── Scans ────────────────────────────────────────────────────────────────────
export async function getScansByUser(userId: number, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scans).where(eq(scans.userId, userId)).orderBy(desc(scans.createdAt)).limit(limit);
}

export async function getScansByTarget(targetId: number, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scans).where(eq(scans.targetId, targetId)).orderBy(desc(scans.createdAt)).limit(limit);
}

export async function getPreviousCompletedScan(targetId: number, beforeScanId: number) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db
    .select()
    .from(scans)
    .where(
      and(
        eq(scans.targetId, targetId),
        eq(scans.status, "completed"),
        sql`${scans.id} < ${beforeScanId}`
      )
    )
    .orderBy(desc(scans.createdAt))
    .limit(1);
  return rows[0] ?? null;
}

export async function getAllScans(limit = 100) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scans).orderBy(desc(scans.createdAt)).limit(limit);
}

export async function getScanById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(scans).where(eq(scans.id, id)).limit(1);
  return result[0];
}

export async function createScan(data: InsertScan) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const result = await db.insert(scans).values(data);
  return (result as any)[0]?.insertId as number;
}

export async function updateScan(id: number, data: Partial<InsertScan>) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.update(scans).set(data).where(eq(scans.id, id));
}

export async function getActiveScans() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scans).where(
    sql`${scans.status} IN ('queued', 'running')`
  ).orderBy(scans.createdAt);
}

export async function countRunningScans(): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  const [row] = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(scans)
    .where(sql`${scans.status} = 'running'`);
  return Number(row?.count ?? 0);
}

export async function getLogsAfterId(scanId: number, afterId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(scanLogs)
    .where(and(eq(scanLogs.scanId, scanId), sql`${scanLogs.id} > ${afterId}`))
    .orderBy(scanLogs.id);
}

/** Mark any scans still "queued" or "running" as failed (e.g. after server restart). Call on startup. */
export async function failStaleScansOnStartup(): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  const now = new Date();
  const result = await db
    .update(scans)
    .set({
      status: "failed",
      completedAt: now,
      errorMessage: "Scan interrupted (server restarted or process ended).",
    })
    .where(sql`${scans.status} = 'running'`);
  // Also fail scan_jobs stuck in running (queued durable jobs are recovered separately)
  try {
    await db.execute(sql.raw(
      "UPDATE scan_jobs SET status='failed', completedAt=NOW(), errorMessage='Interrupted mid-run (process restart)' WHERE status='running'"
    ));
  } catch { /* table may not exist yet */ }
  const row = Array.isArray(result) ? result[0] : result;
  const affected = (row as { affectedRows?: number })?.affectedRows ?? 0;
  if (affected > 0) {
    console.log(`[Startup] Marked ${affected} in-flight scan(s) as failed (queued durable jobs will recover).`);
  }
  return affected;
}

// ─── Scan Findings ────────────────────────────────────────────────────────────
export async function getFindingsByScan(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanFindings).where(eq(scanFindings.scanId, scanId)).orderBy(
    sql`FIELD(${scanFindings.severity}, 'critical', 'high', 'medium', 'low', 'info')`
  );
}

export async function createFindings(data: InsertScanFinding[]) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  if (data.length === 0) return;
  await db.insert(scanFindings).values(data);
}

export async function getFindingById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(scanFindings).where(eq(scanFindings.id, id)).limit(1);
  return result[0];
}

export async function updateFindingStatus(id: number, status: "open" | "acknowledged" | "resolved" | "false_positive") {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.update(scanFindings).set({ status }).where(eq(scanFindings.id, id));
}

export async function getRecentFindingsByUser(userId: number, limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select({ finding: scanFindings, scan: scans })
    .from(scanFindings)
    .innerJoin(scans, eq(scanFindings.scanId, scans.id))
    .where(eq(scans.userId, userId))
    .orderBy(desc(scanFindings.createdAt))
    .limit(limit);
}

// ─── Scan Logs ────────────────────────────────────────────────────────────────
export async function getLogsByScan(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanLogs).where(eq(scanLogs.scanId, scanId)).orderBy(scanLogs.createdAt);
}

export async function appendScanLog(data: InsertScanLog) {
  const db = await getDb();
  if (!db) return;
  await db.insert(scanLogs).values(data);
}

// ─── Schedules ────────────────────────────────────────────────────────────────
export async function getSchedulesByUser(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(schedules).where(eq(schedules.userId, userId)).orderBy(desc(schedules.createdAt));
}

export async function getAllSchedules() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(schedules).where(eq(schedules.enabled, true));
}

export async function getScheduleById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(schedules).where(eq(schedules.id, id)).limit(1);
  return result[0];
}

export async function createSchedule(data: InsertSchedule) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.insert(schedules).values(data);
}

export async function updateSchedule(id: number, data: Partial<InsertSchedule>) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.update(schedules).set(data).where(eq(schedules.id, id));
}

export async function deleteSchedule(id: number) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.delete(schedules).where(eq(schedules.id, id));
}

// ─── Reports ──────────────────────────────────────────────────────────────────
export async function getReportByScan(scanId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(reports).where(eq(reports.scanId, scanId)).limit(1);
  return result[0];
}

export async function getReportsByUser(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(reports).where(eq(reports.userId, userId)).orderBy(desc(reports.generatedAt));
}

export async function getAllReports() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(reports).orderBy(desc(reports.generatedAt));
}

export async function createReport(data: InsertReport) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const result = await db.insert(reports).values(data);
  return (result as any)[0]?.insertId as number;
}

// ─── Dashboard Stats ──────────────────────────────────────────────────────────
export async function getDashboardStats(userId: number, isAdmin: boolean) {
  const db = await getDb();
  if (!db) return null;

  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [totalTargets] = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(targets)
    .where(isAdmin ? undefined : eq(targets.userId, userId));

  const [totalScans] = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(scans)
    .where(isAdmin ? undefined : eq(scans.userId, userId));

  const [recentScans] = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(scans)
    .where(
      isAdmin
        ? gte(scans.createdAt, thirtyDaysAgo)
        : and(eq(scans.userId, userId), gte(scans.createdAt, thirtyDaysAgo))
    );

  const [openFindings] = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(scanFindings)
    .innerJoin(scans, eq(scanFindings.scanId, scans.id))
    .where(
      isAdmin
        ? eq(scanFindings.status, "open")
        : and(eq(scans.userId, userId), eq(scanFindings.status, "open"))
    );

  const [criticalFindings] = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(scanFindings)
    .innerJoin(scans, eq(scanFindings.scanId, scans.id))
    .where(
      isAdmin
        ? and(eq(scanFindings.severity, "critical"), eq(scanFindings.status, "open"))
        : and(eq(scans.userId, userId), eq(scanFindings.severity, "critical"), eq(scanFindings.status, "open"))
    );

  return {
    totalTargets: Number(totalTargets?.count ?? 0),
    totalScans: Number(totalScans?.count ?? 0),
    recentScans: Number(recentScans?.count ?? 0),
    openFindings: Number(openFindings?.count ?? 0),
    criticalFindings: Number(criticalFindings?.count ?? 0),
  };
}

export async function getScanTrends(userId: number, isAdmin: boolean, days = 30) {
  const db = await getDb();
  if (!db) return [];
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const rows = await db
    .select({
      date: sql<string>`DATE(${scans.createdAt})`,
      total: sql<number>`COUNT(*)`,
      completed: sql<number>`SUM(CASE WHEN ${scans.status} = 'completed' THEN 1 ELSE 0 END)`,
      avgScore: sql<number>`AVG(${scans.securityScore})`,
    })
    .from(scans)
    .where(
      isAdmin
        ? gte(scans.createdAt, since)
        : and(eq(scans.userId, userId), gte(scans.createdAt, since))
    )
    .groupBy(sql`DATE(${scans.createdAt})`)
    .orderBy(sql`DATE(${scans.createdAt})`);

  return rows;
}

// ─── Integrations ─────────────────────────────────────────────────────────────
export async function getIntegrationByUser(userId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(integrations).where(eq(integrations.userId, userId)).limit(1);
  return result[0];
}

export async function upsertIntegration(userId: number, configEnc: string, orgId?: number | null) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const existing = await getIntegrationByUser(userId);
  if (existing) {
    await db.update(integrations).set({
      configEnc,
      ...(orgId != null ? { orgId } : {}),
    }).where(eq(integrations.userId, userId));
    return existing.id;
  }
  const result = await db.insert(integrations).values({
    userId,
    configEnc,
    orgId: orgId ?? null,
  } satisfies InsertIntegration);
  return (result as any)[0]?.insertId as number;
}

export async function deleteIntegration(userId: number) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.delete(integrations).where(eq(integrations.userId, userId));
}

export async function getIntegrationByOrg(orgId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(integrations).where(eq(integrations.orgId, orgId)).limit(1);
  return result[0];
}

/** Prefer org-shared config, fall back to user's personal config */
export async function getIntegrationForUser(userId: number, orgId?: number | null) {
  if (orgId) {
    const orgRow = await getIntegrationByOrg(orgId);
    if (orgRow) return orgRow;
  }
  return getIntegrationByUser(userId);
}

// ─── Organizations ────────────────────────────────────────────────────────────
export async function getOrganizationById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(organizations).where(eq(organizations.id, id)).limit(1);
  return rows[0];
}

export async function listOrganizations() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(organizations).orderBy(organizations.name);
}

export async function ensureUserOrg(userId: number): Promise<number | null> {
  const db = await getDb();
  if (!db) return null;
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!user) return null;
  if (user.orgId) return user.orgId;
  const orgs = await listOrganizations();
  const orgId = orgs[0]?.id;
  if (orgId) {
    await db.update(users).set({ orgId }).where(eq(users.id, userId));
    return orgId;
  }
  return null;
}

export async function setUserOrg(userId: number, orgId: number) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.update(users).set({ orgId }).where(eq(users.id, userId));
}

export async function createOrganization(name: string, slug: string) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const result = await db.insert(organizations).values({ name, slug });
  return (result as any)[0]?.insertId as number;
}

// ─── CI/CD API keys ───────────────────────────────────────────────────────────
function hashCicdKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

export async function createCicdApiKey(userId: number, name: string, orgId?: number | null) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const raw = `gs_${randomBytes(24).toString("base64url")}`;
  const keyPrefix = raw.slice(0, 10);
  const keyHash = hashCicdKey(raw);
  const result = await db.insert(cicdApiKeys).values({
    userId,
    orgId: orgId ?? null,
    name,
    keyPrefix,
    keyHash,
  } satisfies InsertCicdApiKey);
  const id = (result as any)[0]?.insertId as number;
  return { id, apiKey: raw, keyPrefix };
}

export async function listCicdApiKeys(userId: number, isAdmin: boolean) {
  const db = await getDb();
  if (!db) return [];
  if (isAdmin) {
    return db.select({
      id: cicdApiKeys.id,
      userId: cicdApiKeys.userId,
      orgId: cicdApiKeys.orgId,
      name: cicdApiKeys.name,
      keyPrefix: cicdApiKeys.keyPrefix,
      lastUsedAt: cicdApiKeys.lastUsedAt,
      revokedAt: cicdApiKeys.revokedAt,
      createdAt: cicdApiKeys.createdAt,
    }).from(cicdApiKeys).orderBy(desc(cicdApiKeys.createdAt));
  }
  return db.select({
    id: cicdApiKeys.id,
    userId: cicdApiKeys.userId,
    orgId: cicdApiKeys.orgId,
    name: cicdApiKeys.name,
    keyPrefix: cicdApiKeys.keyPrefix,
    lastUsedAt: cicdApiKeys.lastUsedAt,
    revokedAt: cicdApiKeys.revokedAt,
    createdAt: cicdApiKeys.createdAt,
  }).from(cicdApiKeys).where(eq(cicdApiKeys.userId, userId)).orderBy(desc(cicdApiKeys.createdAt));
}

export async function revokeCicdApiKey(id: number, userId: number, isAdmin: boolean) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const [row] = await db.select().from(cicdApiKeys).where(eq(cicdApiKeys.id, id)).limit(1);
  if (!row) return false;
  if (!isAdmin && row.userId !== userId) return false;
  await db.update(cicdApiKeys).set({ revokedAt: new Date() }).where(eq(cicdApiKeys.id, id));
  return true;
}

/** Validate raw API key against DB hashes or legacy env CICD_API_KEY. Returns owner userId or 0 for env key. */
export async function validateCicdApiKey(raw: string): Promise<{ ok: boolean; userId: number; orgId: number | null }> {
  const envKey = process.env.CICD_API_KEY;
  if (envKey && envKey.length > 0) {
    const { safeEqual } = await import("./_core/security");
    if (safeEqual(raw, envKey)) return { ok: true, userId: 0, orgId: null };
  }
  const db = await getDb();
  if (!db) return { ok: false, userId: 0, orgId: null };
  const keyHash = hashCicdKey(raw);
  const [row] = await db.select().from(cicdApiKeys).where(eq(cicdApiKeys.keyHash, keyHash)).limit(1);
  if (!row || row.revokedAt) return { ok: false, userId: 0, orgId: null };
  await db.update(cicdApiKeys).set({ lastUsedAt: new Date() }).where(eq(cicdApiKeys.id, row.id));
  return { ok: true, userId: row.userId, orgId: row.orgId ?? null };
}

export async function getTargetsByOrg(orgId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(targets).where(eq(targets.orgId, orgId)).orderBy(desc(targets.createdAt));
}

export async function getScansByOrg(orgId: number, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scans).where(eq(scans.orgId, orgId)).orderBy(desc(scans.createdAt)).limit(limit);
}

export async function getTargetByUrlAndOrg(url: string, orgId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(targets).where(and(eq(targets.orgId, orgId), eq(targets.url, url))).limit(1);
  return rows[0];
}

// ─── Waivers ──────────────────────────────────────────────────────────────────
export async function createFindingWaiver(data: InsertFindingWaiver) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  const fp = data.fingerprint || findingFingerprint(data);
  try {
    const result = await db.insert(findingWaivers).values({ ...data, fingerprint: fp });
    return (result as any)[0]?.insertId as number;
  } catch {
    // upsert on unique (orgId, fingerprint)
    await db.update(findingWaivers).set({
      reason: data.reason,
      expiresAt: data.expiresAt ?? null,
      title: data.title,
      category: data.category ?? null,
      cweId: data.cweId ?? null,
      userId: data.userId,
    }).where(and(eq(findingWaivers.orgId, data.orgId), eq(findingWaivers.fingerprint, fp)));
    const [row] = await db.select().from(findingWaivers)
      .where(and(eq(findingWaivers.orgId, data.orgId), eq(findingWaivers.fingerprint, fp))).limit(1);
    return row?.id ?? 0;
  }
}

export async function listFindingWaivers(orgId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(findingWaivers).where(eq(findingWaivers.orgId, orgId)).orderBy(desc(findingWaivers.createdAt));
}

export async function deleteFindingWaiver(id: number, orgId: number) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.delete(findingWaivers).where(and(eq(findingWaivers.id, id), eq(findingWaivers.orgId, orgId)));
}

export async function getActiveWaiverFingerprints(orgId: number): Promise<Set<string>> {
  const rows = await listFindingWaivers(orgId);
  const now = Date.now();
  const set = new Set<string>();
  for (const w of rows) {
    if (w.expiresAt && new Date(w.expiresAt).getTime() < now) continue;
    set.add(w.fingerprint);
  }
  return set;
}

// ─── Audit ────────────────────────────────────────────────────────────────────
export async function writeAuditEvent(data: InsertAuditEvent) {
  const db = await getDb();
  if (!db) return;
  try {
    await db.insert(auditEvents).values(data);
  } catch (err) {
    console.warn("[audit] write failed:", (err as Error).message);
  }
}

export async function listAuditEvents(orgId: number | null, limit = 100) {
  const db = await getDb();
  if (!db) return [];
  if (orgId == null) {
    return db.select().from(auditEvents).orderBy(desc(auditEvents.createdAt)).limit(limit);
  }
  return db.select().from(auditEvents).where(eq(auditEvents.orgId, orgId)).orderBy(desc(auditEvents.createdAt)).limit(limit);
}

// ─── Scan jobs (durable queue metadata) ───────────────────────────────────────
export async function createScanJob(scanId: number, payload?: Record<string, unknown>) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(scanJobs).values({
    scanId,
    status: "queued",
    payload: payload ?? null,
  } satisfies InsertScanJob);
  return (result as any)[0]?.insertId as number;
}

export async function updateScanJobByScanId(
  scanId: number,
  patch: Partial<{ status: "queued" | "running" | "completed" | "failed"; errorMessage: string | null; startedAt: Date; completedAt: Date }>
) {
  const db = await getDb();
  if (!db) return;
  await db.update(scanJobs).set(patch).where(eq(scanJobs.scanId, scanId));
}

export async function listQueuedScanJobs(limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanJobs).where(eq(scanJobs.status, "queued")).orderBy(scanJobs.createdAt).limit(limit);
}

// ─── Artifacts ────────────────────────────────────────────────────────────────
export async function createScanArtifact(data: InsertScanArtifact) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(scanArtifacts).values(data);
  return (result as any)[0]?.insertId as number;
}

export async function listScanArtifacts(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanArtifacts).where(eq(scanArtifacts.scanId, scanId)).orderBy(desc(scanArtifacts.createdAt));
}

// ─── Org RBAC ─────────────────────────────────────────────────────────────────
export async function setUserOrgRole(
  userId: number,
  orgId: number,
  orgRole: "org_admin" | "member" | "viewer" | "auditor"
) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.update(users).set({ orgId, orgRole }).where(eq(users.id, userId));
}

export async function getUsersByOrg(orgId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(users).where(eq(users.orgId, orgId)).orderBy(users.name);
}

// ─── Scan policies ────────────────────────────────────────────────────────────
export async function listScanPolicies(orgId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanPolicies).where(eq(scanPolicies.orgId, orgId)).orderBy(desc(scanPolicies.createdAt));
}

export async function getScanPolicyById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(scanPolicies).where(eq(scanPolicies.id, id)).limit(1);
  return rows[0];
}

export async function createScanPolicy(data: InsertScanPolicy) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  if (data.isDefault) {
    await db.update(scanPolicies).set({ isDefault: false }).where(eq(scanPolicies.orgId, data.orgId));
  }
  const result = await db.insert(scanPolicies).values(data);
  return (result as any)[0]?.insertId as number;
}

export async function updateScanPolicy(id: number, orgId: number, patch: Partial<InsertScanPolicy>) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  if (patch.isDefault) {
    await db.update(scanPolicies).set({ isDefault: false }).where(eq(scanPolicies.orgId, orgId));
  }
  await db.update(scanPolicies).set(patch).where(and(eq(scanPolicies.id, id), eq(scanPolicies.orgId, orgId)));
}

export async function deleteScanPolicy(id: number, orgId: number) {
  const db = await getDb();
  if (!db) throw new Error("DB unavailable");
  await db.delete(scanPolicies).where(and(eq(scanPolicies.id, id), eq(scanPolicies.orgId, orgId)));
}

export async function getDefaultScanPolicy(orgId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(scanPolicies)
    .where(and(eq(scanPolicies.orgId, orgId), eq(scanPolicies.isDefault, true))).limit(1);
  return rows[0];
}

// ─── Compliance / coverage aggregates ─────────────────────────────────────────
export async function getComplianceCoverage(orgId: number | null, isAdmin: boolean) {
  const db = await getDb();
  if (!db) {
    return { byOwasp: [], bySeverity: [], toolCoverage: [], waiverCount: 0, openFindings: 0, mttrDays: null as number | null };
  }
  const whereOrg = orgId && !isAdmin ? sql`AND s.orgId = ${orgId}` : sql``;
  const owasp = await db.execute(sql.raw(`
    SELECT COALESCE(f.owaspCategory, 'Unmapped') AS label, COUNT(*) AS count
    FROM scan_findings f
    JOIN scans s ON s.id = f.scanId
    WHERE f.status IN ('open','acknowledged') ${orgId && !isAdmin ? `AND s.orgId = ${orgId}` : ""}
    GROUP BY COALESCE(f.owaspCategory, 'Unmapped')
    ORDER BY count DESC
    LIMIT 20
  `));
  const sev = await db.execute(sql.raw(`
    SELECT f.severity AS label, COUNT(*) AS count
    FROM scan_findings f
    JOIN scans s ON s.id = f.scanId
    WHERE f.status IN ('open','acknowledged') ${orgId && !isAdmin ? `AND s.orgId = ${orgId}` : ""}
    GROUP BY f.severity
  `));
  const tools = await db.execute(sql.raw(`
    SELECT TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(s.tools, ',', n.n), ',', -1)) AS tool, COUNT(*) AS scans
    FROM scans s
    JOIN (SELECT 1 n UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10 UNION SELECT 11 UNION SELECT 12) n
      ON n.n <= 1 + LENGTH(s.tools) - LENGTH(REPLACE(s.tools, ',', ''))
    WHERE s.status = 'completed' ${orgId && !isAdmin ? `AND s.orgId = ${orgId}` : ""}
    GROUP BY tool
    HAVING tool <> ''
    ORDER BY scans DESC
    LIMIT 30
  `));
  void whereOrg;
  const waiverRows = orgId
    ? await db.select({ c: sql<number>`COUNT(*)` }).from(findingWaivers).where(eq(findingWaivers.orgId, orgId))
    : await db.select({ c: sql<number>`COUNT(*)` }).from(findingWaivers);
  const openRows = await db.execute(sql.raw(`
    SELECT COUNT(*) AS c FROM scan_findings f JOIN scans s ON s.id = f.scanId
    WHERE f.status = 'open' ${orgId && !isAdmin ? `AND s.orgId = ${orgId}` : ""}
  `));
  const mttr = await db.execute(sql.raw(`
    SELECT AVG(TIMESTAMPDIFF(DAY, f.createdAt, NOW())) AS days
    FROM scan_findings f JOIN scans s ON s.id = f.scanId
    WHERE f.status = 'resolved' ${orgId && !isAdmin ? `AND s.orgId = ${orgId}` : ""}
  `));
  const toArr = (r: any) => (Array.isArray(r) ? (Array.isArray(r[0]) ? r[0] : r) : []) as any[];
  return {
    byOwasp: toArr(owasp).map((x: any) => ({ label: x.label, count: Number(x.count) })),
    bySeverity: toArr(sev).map((x: any) => ({ label: x.label, count: Number(x.count) })),
    toolCoverage: toArr(tools).map((x: any) => ({ tool: x.tool, scans: Number(x.scans) })),
    waiverCount: Number(waiverRows[0]?.c ?? 0),
    openFindings: Number(toArr(openRows)[0]?.c ?? 0),
    mttrDays: toArr(mttr)[0]?.days != null ? Number(toArr(mttr)[0].days) : null,
  };
}

// ─── Artifact retention ───────────────────────────────────────────────────────
export async function listExpiredArtifacts(olderThanDays: number) {
  const db = await getDb();
  if (!db) return [];
  const cutoff = new Date(Date.now() - olderThanDays * 86400000);
  return db.select().from(scanArtifacts).where(sql`${scanArtifacts.createdAt} < ${cutoff}`).limit(500);
}

export async function deleteScanArtifact(id: number) {
  const db = await getDb();
  if (!db) return;
  await db.delete(scanArtifacts).where(eq(scanArtifacts.id, id));
}

export async function getScanArtifactById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(scanArtifacts).where(eq(scanArtifacts.id, id)).limit(1);
  return rows[0];
}

export async function getTargetsByOrgAndEnv(orgId: number, environment: string) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(targets)
    .where(and(eq(targets.orgId, orgId), eq(targets.environment, environment)))
    .orderBy(desc(targets.createdAt));
}
