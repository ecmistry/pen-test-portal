/**
 * Persist raw scanner artifacts locally and optionally to S3.
 */
import { mkdir, writeFile, readFile } from "fs/promises";
import path from "path";
import { createHash } from "crypto";

const LOCAL_ROOT = process.env.ARTIFACT_DIR || path.join(process.cwd(), "data", "artifacts");

export async function storeArtifact(
  scanId: number,
  tool: string,
  data: string | Buffer,
  contentType = "application/json"
): Promise<{ storageKey: string; sizeBytes: number }> {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  const hash = createHash("sha256").update(buf).digest("hex").slice(0, 12);
  const rel = `scan-${scanId}/${tool}-${hash}${contentType.includes("json") ? ".json" : ".txt"}`;
  const abs = path.join(LOCAL_ROOT, rel);
  await mkdir(path.dirname(abs), { recursive: true });
  await writeFile(abs, buf);

  const bucket = process.env.ARTIFACT_S3_BUCKET?.trim();
  if (bucket) {
    try {
      const { S3Client, PutObjectCommand } = await import("@aws-sdk/client-s3");
      const client = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });
      const key = `ghoststrike/${rel}`;
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: buf,
          ContentType: contentType,
        })
      );
      return { storageKey: `s3://${bucket}/${key}`, sizeBytes: buf.length };
    } catch (err) {
      console.warn("[artifacts] S3 upload failed, kept local:", (err as Error).message);
    }
  }

  return { storageKey: `file://${rel}`, sizeBytes: buf.length };
}

export async function readArtifact(storageKey: string): Promise<Buffer | null> {
  try {
    if (storageKey.startsWith("file://")) {
      const rel = storageKey.slice("file://".length);
      return await readFile(path.join(LOCAL_ROOT, rel));
    }
    if (storageKey.startsWith("s3://")) {
      const without = storageKey.slice("s3://".length);
      const slash = without.indexOf("/");
      const bucket = without.slice(0, slash);
      const key = without.slice(slash + 1);
      const { S3Client, GetObjectCommand } = await import("@aws-sdk/client-s3");
      const client = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });
      const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      const bytes = await out.Body?.transformToByteArray();
      return bytes ? Buffer.from(bytes) : null;
    }
    return null;
  } catch {
    return null;
  }
}
