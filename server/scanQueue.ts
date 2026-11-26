/**
 * Global scan concurrency queue — caps simultaneous runScan executions.
 * Persists job metadata to scan_jobs so queued work is visible after restart.
 */

import { createScanJob, updateScanJobByScanId, listQueuedScanJobs, getScanById } from "./db";
import { incCounter, setGauge, observeHistogram } from "./metrics";

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
    }
    Promise.resolve()
      .then(() => next.job())
      .then(() => {
        if (next.scanId) {
          void updateScanJobByScanId(next.scanId, { status: "completed", completedAt: new Date() });
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

/** Enqueue a scan job; resolves when the job finishes (not when it starts). */
export function enqueueScan(job: Job, scanId?: number): Promise<void> {
  return new Promise((resolve, reject) => {
    waiting.push({ job, scanId, resolve, reject, enqueuedAt: Date.now() });
    if (scanId) {
      void createScanJob(scanId, { enqueuedAt: Date.now() });
    }
    incCounter("ghoststrike_scans_enqueued_total");
    getScanQueueStats();
    pump();
  });
}

/** Fire-and-forget enqueue used by routers/schedules */
export function enqueueScanDetached(job: Job, scanId?: number): void {
  enqueueScan(job, scanId).catch((err) => console.error("[ScanQueue] job failed:", err));
}

/**
 * On process start, reconcile orphaned job rows after restart.
 * Closures aren't durable — operators re-trigger remaining queued scans.
 */
export async function recoverScanJobsOnBoot(): Promise<void> {
  try {
    const queued = await listQueuedScanJobs(50);
    for (const job of queued) {
      const scan = await getScanById(job.scanId);
      if (!scan || scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled") {
        await updateScanJobByScanId(job.scanId, {
          status: scan?.status === "completed" ? "completed" : "failed",
          completedAt: new Date(),
          errorMessage: "Recovered after process restart",
        });
      }
    }
  } catch (err) {
    console.warn("[ScanQueue] recovery skipped:", (err as Error).message);
  }
}
