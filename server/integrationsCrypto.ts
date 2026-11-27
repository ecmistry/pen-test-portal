/**
 * Encrypt/decrypt stored ticketing integration configs using JWT_SECRET-derived key.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import type { IntegrationsConfig } from "./ticketingIntegration";

function getKey(): Buffer {
  const secret = process.env.JWT_SECRET || "dev-insecure-jwt-secret";
  return createHash("sha256").update(secret).digest();
}

export function encryptIntegrationsConfig(config: IntegrationsConfig): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", getKey(), iv);
  const plaintext = Buffer.from(JSON.stringify(config), "utf8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

export function decryptIntegrationsConfig(payload: string): IntegrationsConfig {
  const buf = Buffer.from(payload, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", getKey(), iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(decrypted.toString("utf8")) as IntegrationsConfig;
}

/** Redact secrets for API responses */
export function redactIntegrationsConfig(config: IntegrationsConfig): IntegrationsConfig {
  const clone = structuredClone(config);
  if (clone.jira) {
    clone.jira = { ...clone.jira, apiToken: clone.jira.apiToken ? "********" : "" };
  }
  if (clone.github) {
    clone.github = { ...clone.github, token: clone.github.token ? "********" : "" };
  }
  if (clone.linear) {
    clone.linear = { ...clone.linear, apiKey: clone.linear.apiKey ? "********" : "" };
  }
  if (clone.repoScan?.githubToken) {
    clone.repoScan = { ...clone.repoScan, githubToken: "********" };
  }
  return clone;
}
