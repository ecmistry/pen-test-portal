/**
 * Global scan concurrency queue — caps simultaneous runScan executions.
 */

type Job = () => Promise<void>;

const DEFAULT_MAX = Math.max(1, parseInt(process.env.SCAN_MAX_CONCURRENT || "2", 10) || 2);

let maxConcurrent = DEFAULT_MAX;
let active = 0;
const waiting: Array<{ job: Job; resolve: () => void; reject: (e: unknown) => void }> = [];

export function getScanQueueStats() {
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
    Promise.resolve()
      .then(() => next.job())
      .then(() => next.resolve())
      .catch((err) => next.reject(err))
      .finally(() => {
        active--;
        pump();
      });
  }
}

/** Enqueue a scan job; resolves when the job finishes (not when it starts). */
export function enqueueScan(job: Job): Promise<void> {
  return new Promise((resolve, reject) => {
    waiting.push({ job, resolve, reject });
    pump();
  });
}

/** Fire-and-forget enqueue used by routers/schedules */
export function enqueueScanDetached(job: Job): void {
  enqueueScan(job).catch((err) => console.error("[ScanQueue] job failed:", err));
}
