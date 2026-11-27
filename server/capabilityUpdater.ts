/**
 * Daily capability updater — keeps vulnerability/payload intelligence current.
 *
 * Default schedule: **03:00 UTC every day** (`0 0 3 * * *`).
 * Polls once per minute and runs at most once per UTC calendar day.
 *
 * Refreshes:
 *   - Nuclei community templates (`nuclei -update-templates`)
 *   - PayloadsAllTheThings SQLi/XSS lists → data/pen-test-cache.json
 *   - CISA Known Exploited Vulnerabilities (KEV) catalog
 *   - FIRST.org EPSS exploit-probability scores
 *   - Trivy vulnerability DB (when installed)
 *   - NVD details pre-warm for recent KEV CVEs
 *   - Nuclei-templates release metadata
 *
 * Semgrep rules and OSV queries refresh at scan time.
 * External tool binaries (Nikto/ZAP/Nuclei engine) remain operator-updated.
 *
 * Env:
 *   CAPABILITY_AUTO_UPDATE=false     — disable the scheduler
 *   CAPABILITY_UPDATE_CRON="0 0 3 * * *" — 6-field cron in UTC (sec min hour dom mon dow)
 *   CAPABILITY_UPDATE_POLL_MS          — poll interval (default 60s)
 */

import { matchCronField } from "./scheduleRunner";
import { updatePenTestCapabilities, type UpdateResult } from "./penTestUpdater";

/** 03:00:00 UTC daily */
export const DEFAULT_CAPABILITY_CRON = "0 0 3 * * *";
const DEFAULT_POLL_MS = 60_000;

let pollHandle: ReturnType<typeof setInterval> | null = null;
let tickInFlight = false;
let lastResult: UpdateResult | null = null;
let lastRunAt: Date | null = null;
let lastTrigger: "cron" | "manual" | null = null;
/** YYYY-MM-DD (UTC) of last successful/attempted cron fire — prevents double-run in the same minute window */
let lastCronDayUtc: string | null = null;

function envFlagEnabled(name: string, defaultValue = true): boolean {
  const raw = process.env[name];
  if (raw == null || raw === "") return defaultValue;
  return !/^(0|false|no|off)$/i.test(raw.trim());
}

function envMs(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function getCronExpression(): string {
  const raw = process.env.CAPABILITY_UPDATE_CRON?.trim();
  return raw && raw.split(/\s+/).length === 6 ? raw : DEFAULT_CAPABILITY_CRON;
}

/** UTC day key used for once-per-day dedupe */
export function utcDayKey(date: Date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

/** Match a 6-field cron expression against a Date using UTC components */
export function cronMatchesUtc(expression: string, date: Date = new Date()): boolean {
  const parts = expression.trim().split(/\s+/);
  if (parts.length !== 6) return false;
  const [sec, min, hour, dom, mon, dow] = parts;
  return (
    matchCronField(sec, date.getUTCSeconds()) &&
    matchCronField(min, date.getUTCMinutes()) &&
    matchCronField(hour, date.getUTCHours()) &&
    matchCronField(dom, date.getUTCDate()) &&
    matchCronField(mon, date.getUTCMonth() + 1) &&
    matchCronField(dow, date.getUTCDay())
  );
}

/** True when cron matches now and we have not already fired for this UTC day */
export function shouldRunCapabilityCron(
  expression: string,
  now: Date = new Date(),
  alreadyRanDay: string | null = lastCronDayUtc
): boolean {
  if (!cronMatchesUtc(expression, now)) return false;
  return alreadyRanDay !== utcDayKey(now);
}

export async function runCapabilityUpdate(trigger: "cron" | "manual" = "cron"): Promise<UpdateResult> {
  console.log(`[CapabilityUpdater] Starting update (trigger=${trigger})…`);
  const result = await updatePenTestCapabilities();
  lastResult = result;
  lastRunAt = new Date();
  lastTrigger = trigger;
  if (trigger === "cron") {
    lastCronDayUtc = utcDayKey(lastRunAt);
  }

  const parts: string[] = [];
  if (result.payloads) {
    parts.push(`payloads sqli=${result.payloads.sqli} xss=${result.payloads.xss}`);
    if (result.payloads.error) parts.push(`payloadsError=${result.payloads.error}`);
  }
  if (result.nuclei) {
    parts.push(result.nuclei.updated ? `nuclei=updated${result.nuclei.version ? `@${result.nuclei.version}` : ""}` : `nuclei=skipped`);
    if (result.nuclei.error) parts.push(`nucleiError=${result.nuclei.error}`);
  }
  if (result.nucleiRelease?.tag) {
    parts.push(`nucleiTemplates=${result.nucleiRelease.tag}`);
  }
  if (result.kev) parts.push(`kev=${result.kev.count}${result.kev.error ? `!(${result.kev.error})` : ""}`);
  if (result.epss) parts.push(`epss=${result.epss.count}${result.epss.error ? `!(${result.epss.error})` : ""}`);
  if (result.trivyDb) parts.push(result.trivyDb.updated ? "trivyDb=updated" : `trivyDb=skipped`);
  if (result.nvdWarm) parts.push(`nvdWarm=+${result.nvdWarm.fetched}/${result.nvdWarm.cached}`);

  if (result.success) {
    console.log(`[CapabilityUpdater] Complete: ${parts.join(", ") || "ok"}`);
  } else {
    console.warn(`[CapabilityUpdater] Finished with errors: ${parts.join(", ") || "unknown"}`);
  }
  return result;
}

export async function tickCapabilityCron(now: Date = new Date()): Promise<boolean> {
  const expression = getCronExpression();
  if (!shouldRunCapabilityCron(expression, now, lastCronDayUtc)) return false;
  if (tickInFlight) {
    console.log("[CapabilityUpdater] Skipping cron tick — previous update still running");
    return false;
  }
  tickInFlight = true;
  // Mark the day immediately so concurrent polls in the same minute cannot double-fire
  lastCronDayUtc = utcDayKey(now);
  try {
    await runCapabilityUpdate("cron");
    return true;
  } catch (err) {
    console.error("[CapabilityUpdater] cron tick error:", err);
    return false;
  } finally {
    tickInFlight = false;
  }
}

export function startCapabilityUpdater(
  pollMs = envMs("CAPABILITY_UPDATE_POLL_MS", DEFAULT_POLL_MS)
): void {
  if (!envFlagEnabled("CAPABILITY_AUTO_UPDATE", true)) {
    console.log("[CapabilityUpdater] disabled via CAPABILITY_AUTO_UPDATE");
    return;
  }
  if (pollHandle) return;

  const cron = getCronExpression();
  console.log(`[CapabilityUpdater] scheduled cron "${cron}" (UTC), poll every ${Math.round(pollMs / 1000)}s`);

  pollHandle = setInterval(() => {
    void tickCapabilityCron();
  }, pollMs);
  if (typeof pollHandle === "object" && "unref" in pollHandle) {
    (pollHandle as NodeJS.Timeout).unref?.();
  }

  // Immediate check in case we start exactly on the cron minute
  void tickCapabilityCron();
}

export function stopCapabilityUpdater(): void {
  if (pollHandle) {
    clearInterval(pollHandle);
    pollHandle = null;
  }
}

/** Test helper — reset once-per-day guard */
export function clearCapabilityCronGuards(): void {
  lastCronDayUtc = null;
  tickInFlight = false;
}

/** Status for admin / health surfaces */
export function getCapabilityUpdaterStatus() {
  return {
    enabled: envFlagEnabled("CAPABILITY_AUTO_UPDATE", true),
    cron: getCronExpression(),
    timezone: "UTC",
    lastRunAt: lastRunAt?.toISOString() ?? null,
    lastTrigger,
    lastCronDayUtc,
    lastSuccess: lastResult?.success ?? null,
    lastUpdated: lastResult?.lastUpdated ?? null,
    payloads: lastResult?.payloads
      ? { sqli: lastResult.payloads.sqli, xss: lastResult.payloads.xss, error: lastResult.payloads.error }
      : null,
    nuclei: lastResult?.nuclei ?? null,
    nucleiRelease: lastResult?.nucleiRelease ?? null,
  };
}
