/**
 * Schedule runner — evaluates 6-field cron expressions every minute and starts scans.
 * Cron fields: seconds minutes hours day-of-month month weekday
 */

import type { Schedule } from "../drizzle/schema";
import {
  createScan,
  getAllSchedules,
  getTargetById,
  updateSchedule,
} from "./db";
import type { AuthScanConfig, LoginCredentials } from "./scanEngine";
import { enqueueDurableScan } from "./scanQueue";

const runningScheduleIds = new Set<number>();
let intervalHandle: ReturnType<typeof setInterval> | null = null;
let tickInFlight = false;

/** Exported for tests */
export function matchCronField(field: string, value: number): boolean {
  if (field === "*") return true;
  for (const part of field.split(",")) {
    if (part.includes("/")) {
      const [range, stepStr] = part.split("/");
      const step = Number(stepStr);
      if (!Number.isFinite(step) || step <= 0) continue;
      let start = 0;
      let end = value;
      if (range === "*") {
        start = 0;
        end = Number.MAX_SAFE_INTEGER;
      } else if (range.includes("-")) {
        const [a, b] = range.split("-").map(Number);
        start = a;
        end = b;
      } else {
        start = Number(range);
        end = Number.MAX_SAFE_INTEGER;
      }
      if (value >= start && value <= end && (value - start) % step === 0) return true;
      continue;
    }
    if (part.includes("-")) {
      const [a, b] = part.split("-").map(Number);
      if (value >= a && value <= b) return true;
      continue;
    }
    if (Number(part) === value) return true;
  }
  return false;
}

/** Exported for tests — 6-field cron */
export function cronMatches(expression: string, date: Date = new Date()): boolean {
  const parts = expression.trim().split(/\s+/);
  if (parts.length !== 6) return false;
  const [sec, min, hour, dom, mon, dow] = parts;
  return (
    matchCronField(sec, date.getSeconds()) &&
    matchCronField(min, date.getMinutes()) &&
    matchCronField(hour, date.getHours()) &&
    matchCronField(dom, date.getDate()) &&
    matchCronField(mon, date.getMonth() + 1) &&
    matchCronField(dow, date.getDay())
  );
}

/** Avoid re-firing in the same minute after lastRunAt */
export function shouldRunSchedule(schedule: Pick<Schedule, "cronExpression" | "lastRunAt" | "enabled">, now = new Date()): boolean {
  if (!schedule.enabled) return false;
  if (!cronMatches(schedule.cronExpression, now)) return false;
  if (schedule.lastRunAt) {
    const last = new Date(schedule.lastRunAt);
    const sameMinute =
      last.getFullYear() === now.getFullYear() &&
      last.getMonth() === now.getMonth() &&
      last.getDate() === now.getDate() &&
      last.getHours() === now.getHours() &&
      last.getMinutes() === now.getMinutes();
    if (sameMinute) return false;
  }
  return true;
}

function computeNextRunHint(from = new Date()): Date {
  return new Date(from.getTime() + 60_000);
}

export async function triggerScheduledScan(schedule: Schedule): Promise<number | null> {
  if (runningScheduleIds.has(schedule.id)) return null;
  runningScheduleIds.add(schedule.id);
  try {
    const target = await getTargetById(schedule.targetId);
    if (!target || !target.isActive) {
      await updateSchedule(schedule.id, { lastRunAt: new Date(), nextRunAt: computeNextRunHint() });
      return null;
    }

    const tools = (schedule.tools || "headers,auth,sqli,xss")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    const scanMode = (schedule as Schedule & { scanMode?: string }).scanMode === "full" ? "full" : "light";

    const authConfig = (target as typeof target & { authConfig?: AuthScanConfig | null }).authConfig ?? undefined;
    const loginCredentials = authConfig && (authConfig as AuthScanConfig & { loginCredentials?: LoginCredentials }).loginCredentials
      ? (authConfig as AuthScanConfig & { loginCredentials?: LoginCredentials }).loginCredentials
      : undefined;

    // Prefer structured authConfig.authProfiles; loginCredentials may be nested for convenience
    const profilesConfig: AuthScanConfig | undefined = authConfig
      ? {
          authProfiles: authConfig.authProfiles,
          authTests: authConfig.authTests,
        }
      : undefined;

    const manifestPath =
      (target as typeof target & { manifestPath?: string | null }).manifestPath ?? undefined;
    const openapiUrl =
      (target as typeof target & { openapiUrl?: string | null }).openapiUrl ?? undefined;

    const scanId = await createScan({
      targetId: target.id,
      userId: schedule.userId,
      status: "queued",
      tools: tools.join(","),
      scanMode,
      triggeredBy: "schedule",
    });

    await updateSchedule(schedule.id, {
      lastRunAt: new Date(),
      nextRunAt: computeNextRunHint(),
    });

    enqueueDurableScan({
      scanId,
      targetId: target.id,
      targetUrl: target.url,
      tools,
      scanMode,
      authConfig: profilesConfig,
      manifestPath: manifestPath ?? undefined,
      loginCredentials,
      repoUrl: target.repoUrl ?? undefined,
      repoBranch: (target as any).repoBranch ?? undefined,
      repoRef: (target as any).repoRef ?? undefined,
      repoSubpath: (target as any).repoSubpath ?? undefined,
      openapiUrl: openapiUrl ?? undefined,
      scheduleId: schedule.id,
      userId: schedule.userId,
    });
    // Clear running lock after a short delay; durable job owns execution
    setTimeout(() => runningScheduleIds.delete(schedule.id), 5000);

    return scanId;
  } catch (err) {
    runningScheduleIds.delete(schedule.id);
    console.error("[ScheduleRunner] trigger failed:", err);
    return null;
  }
}

export async function tickSchedules(now = new Date()): Promise<number[]> {
  const schedules = await getAllSchedules();
  const started: number[] = [];
  for (const schedule of schedules) {
    if (!shouldRunSchedule(schedule, now)) continue;
    if (runningScheduleIds.has(schedule.id)) continue;
    const scanId = await triggerScheduledScan(schedule);
    if (scanId != null) started.push(scanId);
  }
  return started;
}

export function startScheduleRunner(intervalMs = 60_000): void {
  if (intervalHandle) return;
  console.log("[ScheduleRunner] started (interval", intervalMs, "ms)");
  intervalHandle = setInterval(() => {
    if (tickInFlight) return;
    tickInFlight = true;
    tickSchedules()
      .catch((err) => console.error("[ScheduleRunner] tick error:", err))
      .finally(() => {
        tickInFlight = false;
      });
  }, intervalMs);
  // Unref so Vitest/process can exit cleanly when appropriate
  if (typeof intervalHandle === "object" && "unref" in intervalHandle) {
    (intervalHandle as NodeJS.Timeout).unref?.();
  }
}

export function stopScheduleRunner(): void {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
}

/** Test helper */
export function clearRunningScheduleGuards(): void {
  runningScheduleIds.clear();
}
