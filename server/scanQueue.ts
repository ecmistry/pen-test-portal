/**
 * Durable scan concurrency queue.
 * Jobs are persisted with a serializable payload so queued work can resume after restart.
 */

import {
  createScanJob,
  updateScanJobByScanId,
  listQueuedScanJobs,
  getScanById,
  updateScan,
} from "./db";
import { incCounter, setGauge, observeHistogram } from "./metrics";
import type { ScanJobPayload } from "./scanJobPayload";

type Job = () => Promise<void>;

const DEFAULT_MAX = Math.max(1, parseInt(process.env.SCAN_MAX_CONCURRENT || "2", 10) || 2);

let maxConcurrent = DEFAULT_MAX;
let active = 0;
const waiting: Array<{
  job: Job;
  scanId?: number;
  resolve: () => void;
  reject: (e: unknown) => void;
  enqueuedAt: number;
}> = [];

/** In-flight scanIds to avoid double-enqueue on recovery */
const knownScanIds = new Set<number>();

export function getScanQueueStats() {
  setGauge("ghoststrike_scan_queue_active", active);
  setGauge("ghoststrike_scan_queue_waiting", waiting.length);
  setGauge("ghoststrike_scan_queue_max", maxConcurrent);
  return { active, waiting: waiting.length, maxConcurrent };
}

export function setScanMaxConcurrent(n: number) {
  maxConcurrent = Math.max(1, Math.min(16, Math.floor(n)));
  pump();
}

function pump() {
  while (active < maxConcurrent && waiting.length > 0) {
    const next = waiting.shift()!;
    active++;
    getScanQueueStats();
    const started = Date.now();
    if (next.scanId) {
      void updateScanJobByScanId(next.scanId, { status: "running", startedAt: new Date() });
      void updateScan(next.scanId, { status: "running", startedAt: new Date() }).catch(() => undefined);
    }
    Promise.resolve()
      .then(() => next.job())
      .then(() => {
        if (next.scanId) {
          void updateScanJobByScanId(next.scanId, { status: "completed", completedAt: new Date() });
          knownScanIds.delete(next.scanId);
        }
        next.resolve();
      })
      .catch((err) => {
        if (next.scanId) {
          void updateScanJobByScanId(next.scanId, {
            status: "failed",
            completedAt: new Date(),
            errorMessage: (err as Error)?.message || String(err),
          });
          knownScanIds.delete(next.scanId);
        }
        next.reject(err);
      })
      .finally(() => {
        active--;
        observeHistogram("ghoststrike_scan_duration_ms", Date.now() - started);
        getScanQueueStats();
        pump();
      });
  }
}

export function enqueueScan(job: Job, scanId?: number, payload?: ScanJobPayload): Promise<void> {
  return new Promise((resolve, reject) => {
    if (scanId) knownScanIds.add(scanId);
    waiting.push({ job, scanId, resolve, reject, enqueuedAt: Date.now() });
    if (scanId) {
      void createScanJob(scanId, (payload as Record<string, unknown>) ?? { enqueuedAt: Date.now() });
    }
    incCounter("ghoststrike_scans_enqueued_total");
    getScanQueueStats();
    pump();
  });
}

export function enqueueScanDetached(job: Job, scanId?: number, payload?: ScanJobPayload): void {
  enqueueScan(job, scanId, payload).catch((err) => console.error("[ScanQueue] job failed:", err));
}

/** Preferred entry: persist payload and reconstruct runScan on recovery */
export function enqueueDurableScan(payload: ScanJobPayload): void {
  const job = async () => {
    const { runScan } = await import("./scanEngine");
    await runScan(
      payload.scanId,
      payload.targetId,
      payload.targetUrl,
      payload.tools,
      (payload.scanMode as "light" | "full") || "light",
      payload.authConfig as any,
      payload.manifestPath || undefined,
      payload.loginCredentials as any,
      payload.repoUrl || undefined,
      payload.openapiUrl || undefined
    );

    if (payload.scheduleId) {
      try {
        const { getIntegrationForUser, getFindingsByScan, getScanById, getTargetById, getScheduleById } = await import("./db");
        const schedule = await getScheduleById(payload.scheduleId);
        if ((schedule as any)?.autoPushTicketing) {
          const { decryptIntegrationsConfig } = await import("./integrationsCrypto");
          const { pushFindingsToTicketing } = await import("./ticketingIntegration");
          const integ = await getIntegrationForUser(payload.userId || schedule!.userId, undefined);
          if (integ?.configEnc) {
            const config = decryptIntegrationsConfig(integ.configEnc);
            const findings = await getFindingsByScan(payload.scanId);
            const scan = await getScanById(payload.scanId);
            const t = scan ? await getTargetById(scan.targetId) : null;
            await pushFindingsToTicketing(config, findings, t?.url ?? payload.targetUrl, false);
          }
        }
      } catch (err) {
        console.warn("[ScanQueue] schedule post-hooks failed:", (err as Error).message);
      }
    }
  };
  enqueueScanDetached(job, payload.scanId, payload);
}

/**
 * Re-enqueue queued durable jobs after restart.
 * Running scans without a live process are marked failed (cannot resume mid-tool).
 */
export async function recoverScanJobsOnBoot(): Promise<void> {
  try {
    const queued = await listQueuedScanJobs(100);
    let recovered = 0;
    for (const row of queued) {
      if (knownScanIds.has(row.scanId)) continue;
      const scan = await getScanById(row.scanId);
      const payload = row.payload as ScanJobPayload | null;
      if (!payload?.scanId || !payload.targetUrl || !Array.isArray(payload.tools)) {
        await updateScanJobByScanId(row.scanId, {
          status: "failed",
          completedAt: new Date(),
          errorMessage: "Missing durable payload; cannot recover",
        });
        if (scan && (scan.status === "queued" || scan.status === "running")) {
          await updateScan(row.scanId, {
            status: "failed",
            completedAt: new Date(),
            errorMessage: "Scan interrupted (no durable payload).",
          });
        }
        continue;
      }
      if (scan && (scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled")) {
        await updateScanJobByScanId(row.scanId, {
          status: scan.status === "completed" ? "completed" : "failed",
          completedAt: new Date(),
        });
        continue;
      }
      // Reset scan to queued and re-run
      await updateScan(row.scanId, { status: "queued", errorMessage: null });
      await updateScanJobByScanId(row.scanId, { status: "queued", errorMessage: null });
      enqueueDurableScan(payload);
      recovered++;
    }
    if (recovered > 0) console.log(`[ScanQueue] Recovered ${recovered} durable scan job(s)`);
  } catch (err) {
    console.warn("[ScanQueue] recovery skipped:", (err as Error).message);
  }
}
