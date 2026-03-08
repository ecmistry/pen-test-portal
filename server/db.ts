import { and, desc, eq, gte, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  InsertReport,
  InsertScan,
  InsertScanFinding,
  InsertScanLog,
  InsertSchedule,
  InsertTarget,
  InsertUser,
  reports,
  scanFindings,
  scanLogs,
  scans,
  schedules,
  targets,
  users,
} from "../drizzle/schema";
import { ENV } from "./_core/env";

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
  await safeAlter("ALTER TABLE reports MODIFY markdownContent MEDIUMTEXT");
  await safeAlter("ALTER TABLE reports MODIFY executiveSummary MEDIUMTEXT");
  await safeAlter("ALTER TABLE reports MODIFY complianceNotes MEDIUMTEXT");
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
    .where(sql`${scans.status} IN ('queued', 'running')`);
  const row = Array.isArray(result) ? result[0] : result;
  const affected = (row as { affectedRows?: number })?.affectedRows ?? 0;
  if (affected > 0) {
    console.log(`[Startup] Marked ${affected} stale scan(s) as failed.`);
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
