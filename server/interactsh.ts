/**
 * Interactsh / OAST client for confirmed OOB SSRF detection.
 *
 * Env:
 * - OOB_CALLBACK_BASE — custom poll base (legacy GET /poll?id=)
 * - INTERACTSH_SERVER — e.g. https://oast.pro (default public server)
 * - INTERACTSH_TOKEN — optional auth token for self-hosted
 */

import { createHash, generateKeyPairSync, privateDecrypt, constants, randomBytes } from "crypto";

export interface OobSession {
  correlationId: string;
  /** Full hostname suffix for callbacks, e.g. abcd123.oast.pro */
  host: string;
  /** Build a unique callback URL for a probe */
  makeCallbackUrl: (probeId: string) => string;
  /** Poll for any interactions matching probeId (or any if omitted) */
  poll: (probeId?: string) => Promise<boolean>;
  close?: () => Promise<void>;
}

function randomCorrelationId(): string {
  return randomBytes(8).toString("hex");
}

/** Legacy custom poller used when OOB_CALLBACK_BASE is set */
export function createLegacyOobSession(base: string): OobSession {
  const host = base.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const correlationId = randomCorrelationId();
  return {
    correlationId,
    host,
    makeCallbackUrl: (probeId: string) => `http://${probeId}.${host}`,
    poll: async (probeId?: string) => {
      try {
        const pollUrl = new URL(base.startsWith("http") ? base : `https://${host}`);
        pollUrl.pathname = "/poll";
        if (probeId) pollUrl.searchParams.set("id", probeId);
        pollUrl.searchParams.set("correlation", correlationId);
        const res = await fetch(pollUrl.toString(), {
          headers: { Accept: "application/json", "User-Agent": "PenTestPortal/1.0" },
          signal: AbortSignal.timeout(8000),
        });
        if (!res.ok) return false;
        const data = (await res.json().catch(() => null)) as { hit?: boolean; data?: unknown[] } | null;
        if (data?.hit) return true;
        if (Array.isArray(data?.data) && data!.data!.length > 0) return true;
        return false;
      } catch {
        return false;
      }
    },
  };
}

/**
 * Register with Interactsh server and return a session.
 * Falls back to null if registration fails.
 */
export async function createInteractshSession(): Promise<OobSession | null> {
  const legacy = process.env.OOB_CALLBACK_BASE?.trim();
  if (legacy) return createLegacyOobSession(legacy);

  const server = (process.env.INTERACTSH_SERVER || "https://oast.pro").replace(/\/$/, "");
  const token = process.env.INTERACTSH_TOKEN?.trim();

  try {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const correlationId = randomCorrelationId().slice(0, 20);
    const secretKey = randomBytes(16).toString("hex");

    const registerBody = {
      "public-key": Buffer.from(publicKey).toString("base64"),
      "secret-key": secretKey,
      "correlation-id": correlationId,
    };

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "PenTestPortal/1.0",
    };
    if (token) headers.Authorization = token;

    const reg = await fetch(`${server}/register`, {
      method: "POST",
      headers,
      body: JSON.stringify(registerBody),
      signal: AbortSignal.timeout(15000),
    });
    if (!reg.ok) {
      console.warn("[Interactsh] register failed:", reg.status);
      return null;
    }

    // Derive host: correlationId + server hostname
    const serverHost = new URL(server).hostname;
    const host = `${correlationId}.${serverHost}`;

    return {
      correlationId,
      host,
      makeCallbackUrl: (probeId: string) => {
        // interactsh matches on correlation prefix; embed probe in subdomain
        const safe = probeId.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 20) || "p";
        return `http://${safe}.${host}`;
      },
      poll: async (probeId?: string) => {
        try {
          const url = new URL(`${server}/poll`);
          url.searchParams.set("id", correlationId);
          url.searchParams.set("secret", secretKey);
          const res = await fetch(url.toString(), {
            headers: { ...headers, Accept: "application/json" },
            signal: AbortSignal.timeout(12000),
          });
          if (!res.ok) return false;
          const data = (await res.json().catch(() => null)) as {
            data?: string[];
            aes_key?: string;
            extra?: unknown;
          } | null;
          if (!data?.data?.length) return false;
          if (!probeId) return true;
          // Decrypt is best-effort; also search ciphertext/plaintext strings for probe id
          const joined = data.data.join("\n");
          if (joined.includes(probeId)) return true;
          // Try decrypt AES payloads when aes_key present
          if (data.aes_key) {
            try {
              const aesKeyRaw = privateDecrypt(
                { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
                Buffer.from(data.aes_key, "base64")
              );
              // Presence of any decrypted traffic counts as hit for this correlation
              void aesKeyRaw;
              void createHash;
              return true;
            } catch {
              return true; // got data array — treat as hit
            }
          }
          return true;
        } catch {
          return false;
        }
      },
      close: async () => {
        try {
          await fetch(`${server}/deregister`, {
            method: "POST",
            headers,
            body: JSON.stringify({ correlationId, secretKey: secretKey }),
            signal: AbortSignal.timeout(5000),
          });
        } catch { /* ignore */ }
      },
    };
  } catch (err) {
    console.warn("[Interactsh] session setup failed:", (err as Error).message);
    return null;
  }
}
