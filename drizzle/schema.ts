import {
  boolean,
  decimal,
  int,
  json,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/mysql-core";

// ─── Users ────────────────────────────────────────────────────────────────────
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

// ─── Targets ──────────────────────────────────────────────────────────────────
export const targets = mysqlTable("targets", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  url: varchar("url", { length: 2048 }).notNull(),
  description: text("description"),
  tags: varchar("tags", { length: 500 }),
  scanFrequency: mysqlEnum("scanFrequency", ["manual", "daily", "weekly", "monthly"]).default("manual").notNull(),
  isActive: boolean("isActive").default(true).notNull(),
  lastScannedAt: timestamp("lastScannedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Target = typeof targets.$inferSelect;
export type InsertTarget = typeof targets.$inferInsert;

// ─── Scans ────────────────────────────────────────────────────────────────────
export const scans = mysqlTable("scans", {
  id: int("id").autoincrement().primaryKey(),
  targetId: int("targetId").notNull(),
  userId: int("userId").notNull(),
  status: mysqlEnum("status", ["queued", "running", "completed", "failed", "cancelled"]).default("queued").notNull(),
  tools: varchar("tools", { length: 500 }).notNull().default("headers,auth,sqli,xss"),
  scanMode: varchar("scanMode", { length: 20 }).default("light").notNull(),
  securityScore: int("securityScore"),
  riskLevel: mysqlEnum("riskLevel", ["critical", "high", "medium", "low", "info"]),
  totalFindings: int("totalFindings").default(0),
  criticalCount: int("criticalCount").default(0),
  highCount: int("highCount").default(0),
  mediumCount: int("mediumCount").default(0),
  lowCount: int("lowCount").default(0),
  infoCount: int("infoCount").default(0),
  startedAt: timestamp("startedAt"),
  completedAt: timestamp("completedAt"),
  errorMessage: text("errorMessage"),
  triggeredBy: mysqlEnum("triggeredBy", ["manual", "schedule"]).default("manual").notNull(),
  scenarios: json("scenarios"),
  trendSummary: json("trendSummary"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Scan = typeof scans.$inferSelect;
export type InsertScan = typeof scans.$inferInsert;

// ─── Scan Findings ────────────────────────────────────────────────────────────
export const scanFindings = mysqlTable("scan_findings", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  category: varchar("category", { length: 100 }).notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low", "info"]).notNull(),
  title: varchar("title", { length: 500 }).notNull(),
  description: text("description"),
  evidence: text("evidence"),
  recommendation: text("recommendation"),
  cweId: varchar("cweId", { length: 20 }),
  owaspCategory: varchar("owaspCategory", { length: 100 }),
  cvssVector: varchar("cvssVector", { length: 200 }),
  cvssScore: decimal("cvssScore", { precision: 3, scale: 1 }),
  remediationComplexity: varchar("remediationComplexity", { length: 20 }),
  remediationPriority: varchar("remediationPriority", { length: 10 }),
  businessImpact: json("businessImpact"),
  attackTechniques: json("attackTechniques"),
  iso27001Controls: json("iso27001Controls"),
  poc: json("poc"),
  status: mysqlEnum("status", ["open", "acknowledged", "resolved", "false_positive"]).default("open").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ScanFinding = typeof scanFindings.$inferSelect;
export type InsertScanFinding = typeof scanFindings.$inferInsert;

// ─── Scan Logs ────────────────────────────────────────────────────────────────
export const scanLogs = mysqlTable("scan_logs", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  level: mysqlEnum("level", ["info", "warn", "error", "success", "debug"]).default("info").notNull(),
  message: text("message").notNull(),
  phase: varchar("phase", { length: 100 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ScanLog = typeof scanLogs.$inferSelect;
export type InsertScanLog = typeof scanLogs.$inferInsert;

// ─── Schedules ────────────────────────────────────────────────────────────────
export const schedules = mysqlTable("schedules", {
  id: int("id").autoincrement().primaryKey(),
  targetId: int("targetId").notNull(),
  userId: int("userId").notNull(),
  cronExpression: varchar("cronExpression", { length: 100 }).notNull(),
  tools: varchar("tools", { length: 500 }).notNull().default("headers,auth,sqli,xss"),
  enabled: boolean("enabled").default(true).notNull(),
  lastRunAt: timestamp("lastRunAt"),
  nextRunAt: timestamp("nextRunAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Schedule = typeof schedules.$inferSelect;
export type InsertSchedule = typeof schedules.$inferInsert;

// ─── Reports ──────────────────────────────────────────────────────────────────
export const reports = mysqlTable("reports", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  userId: int("userId").notNull(),
  title: varchar("title", { length: 500 }).notNull(),
  executiveSummary: text("executiveSummary"),
  markdownContent: text("markdownContent"),
  jsonContent: json("jsonContent"),
  complianceNotes: text("complianceNotes"),
  generatedAt: timestamp("generatedAt").defaultNow().notNull(),
});

export type Report = typeof reports.$inferSelect;
export type InsertReport = typeof reports.$inferInsert;
