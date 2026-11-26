import {
  boolean,
  decimal,
  int,
  json,
  mediumtext,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/mysql-core";

// ─── Organizations (basic multi-tenant) ───────────────────────────────────────
export const organizations = mysqlTable("organizations", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  slug: varchar("slug", { length: 100 }).notNull().unique(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Organization = typeof organizations.$inferSelect;
export type InsertOrganization = typeof organizations.$inferInsert;

// ─── Users ────────────────────────────────────────────────────────────────────
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  /** Org-scoped RBAC: org_admin | member | viewer | auditor */
  orgRole: mysqlEnum("orgRole", ["org_admin", "member", "viewer", "auditor"]).default("member"),
  orgId: int("orgId"),
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
  orgId: int("orgId"),
  name: varchar("name", { length: 255 }).notNull(),
  url: varchar("url", { length: 2048 }).notNull(),
  repoUrl: varchar("repoUrl", { length: 2048 }),
  description: text("description"),
  tags: varchar("tags", { length: 500 }),
  /** Logical environment: development | staging | production | custom */
  environment: varchar("environment", { length: 64 }).default("production"),
  /** Optional org scan policy id for defaults */
  policyId: int("policyId"),
  scanFrequency: mysqlEnum("scanFrequency", ["manual", "daily", "weekly", "monthly"]).default("manual").notNull(),
  isActive: boolean("isActive").default(true).notNull(),
  /** Default multi-role auth + login credentials for scheduled/CI scans */
  authConfig: json("authConfig"),
  /** Optional OpenAPI/Swagger URL for API inventory driven testing */
  openapiUrl: varchar("openapiUrl", { length: 2048 }),
  /** Optional local lockfile/manifest path for SCA */
  manifestPath: varchar("manifestPath", { length: 500 }),
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
  authMode: varchar("authMode", { length: 20 }),
  authMeta: json("authMeta"),
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
  triggeredBy: mysqlEnum("triggeredBy", ["manual", "schedule", "cicd", "retest"]).default("manual").notNull(),
  orgId: int("orgId"),
  /** When set, this scan is a retest of a prior finding */
  parentFindingId: int("parentFindingId"),
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
  affectedUrl: text("affectedUrl"),
  affectedComponent: varchar("affectedComponent", { length: 200 }),
  sourceFile: varchar("sourceFile", { length: 500 }),
  sourceLine: int("sourceLine"),
  sourceSnippet: text("sourceSnippet"),
  authContext: varchar("authContext", { length: 20 }),
  /** confirmed | likely | heuristic — exploitability / evidence strength */
  confidence: varchar("confidence", { length: 20 }),
  /** External scanner rule/template id (Nuclei template-id, ZAP pluginid, Semgrep check_id) */
  templateId: varchar("templateId", { length: 255 }),
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
  scanMode: varchar("scanMode", { length: 20 }).default("light").notNull(),
  autoPushTicketing: boolean("autoPushTicketing").default(false).notNull(),
  enabled: boolean("enabled").default(true).notNull(),
  lastRunAt: timestamp("lastRunAt"),
  nextRunAt: timestamp("nextRunAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Schedule = typeof schedules.$inferSelect;
export type InsertSchedule = typeof schedules.$inferInsert;

// ─── Integrations (ticketing + webhooks; org-scoped preferred) ───────────────
export const integrations = mysqlTable("integrations", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().unique(),
  orgId: int("orgId"),
  /** AES-GCM encrypted IntegrationsConfig JSON */
  configEnc: text("configEnc").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Integration = typeof integrations.$inferSelect;
export type InsertIntegration = typeof integrations.$inferInsert;

// ─── Finding waivers (org-scoped suppressions by fingerprint) ─────────────────
export const findingWaivers = mysqlTable("finding_waivers", {
  id: int("id").autoincrement().primaryKey(),
  orgId: int("orgId").notNull(),
  userId: int("userId").notNull(),
  fingerprint: varchar("fingerprint", { length: 255 }).notNull(),
  title: varchar("title", { length: 500 }).notNull(),
  category: varchar("category", { length: 100 }),
  cweId: varchar("cweId", { length: 20 }),
  reason: text("reason"),
  expiresAt: timestamp("expiresAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type FindingWaiver = typeof findingWaivers.$inferSelect;
export type InsertFindingWaiver = typeof findingWaivers.$inferInsert;

// ─── Audit events ─────────────────────────────────────────────────────────────
export const auditEvents = mysqlTable("audit_events", {
  id: int("id").autoincrement().primaryKey(),
  orgId: int("orgId"),
  userId: int("userId"),
  action: varchar("action", { length: 100 }).notNull(),
  resourceType: varchar("resourceType", { length: 64 }),
  resourceId: varchar("resourceId", { length: 64 }),
  meta: json("meta"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type AuditEvent = typeof auditEvents.$inferSelect;
export type InsertAuditEvent = typeof auditEvents.$inferInsert;

// ─── Durable scan jobs (survives process restart metadata) ────────────────────
export const scanJobs = mysqlTable("scan_jobs", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  status: mysqlEnum("status", ["queued", "running", "completed", "failed"]).default("queued").notNull(),
  payload: json("payload"),
  errorMessage: text("errorMessage"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  startedAt: timestamp("startedAt"),
  completedAt: timestamp("completedAt"),
});

export type ScanJob = typeof scanJobs.$inferSelect;
export type InsertScanJob = typeof scanJobs.$inferInsert;

// ─── Scanner artifacts (raw tool output paths/keys) ───────────────────────────
export const scanArtifacts = mysqlTable("scan_artifacts", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  tool: varchar("tool", { length: 64 }).notNull(),
  contentType: varchar("contentType", { length: 128 }).default("application/json").notNull(),
  storageKey: varchar("storageKey", { length: 512 }).notNull(),
  sizeBytes: int("sizeBytes").default(0),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ScanArtifact = typeof scanArtifacts.$inferSelect;
export type InsertScanArtifact = typeof scanArtifacts.$inferInsert;

// ─── CI/CD API keys (hashed at rest) ──────────────────────────────────────────
export const cicdApiKeys = mysqlTable("cicd_api_keys", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  orgId: int("orgId"),
  name: varchar("name", { length: 255 }).notNull(),
  keyPrefix: varchar("keyPrefix", { length: 16 }).notNull(),
  keyHash: varchar("keyHash", { length: 128 }).notNull(),
  lastUsedAt: timestamp("lastUsedAt"),
  revokedAt: timestamp("revokedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type CicdApiKey = typeof cicdApiKeys.$inferSelect;
export type InsertCicdApiKey = typeof cicdApiKeys.$inferInsert;

// ─── Reports ──────────────────────────────────────────────────────────────────
export const reports = mysqlTable("reports", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  userId: int("userId").notNull(),
  title: varchar("title", { length: 500 }).notNull(),
  executiveSummary: mediumtext("executiveSummary"),
  markdownContent: mediumtext("markdownContent"),
  jsonContent: json("jsonContent"),
  complianceNotes: mediumtext("complianceNotes"),
  generatedAt: timestamp("generatedAt").defaultNow().notNull(),
});

export type Report = typeof reports.$inferSelect;
export type InsertReport = typeof reports.$inferInsert;

// ─── Org scan policy profiles ─────────────────────────────────────────────────
export const scanPolicies = mysqlTable("scan_policies", {
  id: int("id").autoincrement().primaryKey(),
  orgId: int("orgId").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  tools: varchar("tools", { length: 500 }).notNull(),
  scanMode: varchar("scanMode", { length: 20 }).default("light").notNull(),
  failOnSeverity: varchar("failOnSeverity", { length: 20 }).default("high").notNull(),
  onlyNew: boolean("onlyNew").default(true).notNull(),
  isDefault: boolean("isDefault").default(false).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type ScanPolicy = typeof scanPolicies.$inferSelect;
export type InsertScanPolicy = typeof scanPolicies.$inferInsert;
