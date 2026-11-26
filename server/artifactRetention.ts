/**
 * Periodic cleanup of old scanner artifacts.
 */
import { unlink } from "fs/promises";
import path from "path";
import { deleteScanArtifact, listExpiredArtifacts } from "./db";

const LOCAL_ROOT = process.env.ARTIFACT_DIR || path.join(process.cwd(), "data", "artifacts");

export async function runArtifactRetention(olderThanDays = Number(process.env.ARTIFACT_RETENTION_DAYS || 30)): Promise<number> {
  const days = Math.max(1, olderThanDays);
  const rows = await listExpiredArtifacts(days);
  let removed = 0;
  for (const row of rows) {
    try {
      if (row.storageKey.startsWith("file://")) {
        const rel = row.storageKey.slice("file://".length);
        await unlink(path.join(LOCAL_ROOT, rel)).catch(() => undefined);
      }
      // S3 lifecycle should handle s3:// keys; we still drop DB rows
      await deleteScanArtifact(row.id);
      removed++;
    } catch (err) {
      console.warn("[retention] failed for artifact", row.id, (err as Error).message);
    }
  }
  if (removed) console.log(`[retention] Removed ${removed} artifact(s) older than ${days}d`);
  return removed;
}

export function startArtifactRetentionScheduler(intervalMs = 6 * 60 * 60 * 1000) {
  const tick = () => {
    runArtifactRetention().catch((err) => console.warn("[retention]", err?.message || err));
  };
  setTimeout(tick, 60_000);
  setInterval(tick, intervalMs);
}
