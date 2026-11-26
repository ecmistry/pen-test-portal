/**
 * Slack / Teams / generic webhook dispatcher for scan lifecycle events.
 * Also fans out to the env-configured n8n operations-security-alerts webhook.
 */
import { createHmac } from "crypto";
import type { IntegrationsConfig } from "./ticketingIntegration";
import { n8nAlertFromScanEvent, sendN8nSecurityAlert } from "./n8nAlerts";

export type WebhookEvent =
  | "scan.completed"
  | "scan.failed"
  | "gate.failed"
  | "finding.critical";

export interface WebhookEndpoint {
  url: string;
  secret?: string;
  events?: WebhookEvent[];
  /** slack | teams | generic */
  type?: "slack" | "teams" | "generic";
}

export interface WebhookPayload {
  event: WebhookEvent;
  scanId: number;
  targetName?: string;
  targetUrl?: string;
  status?: string;
  securityScore?: number | null;
  riskLevel?: string | null;
  criticalCount?: number;
  highCount?: number;
  message: string;
}

function sign(secret: string, body: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function formatSlack(p: WebhookPayload) {
  return {
    text: p.message,
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Ghoststrike* — ${p.message}\nScan #${p.scanId}${p.targetName ? ` · ${p.targetName}` : ""}${p.securityScore != null ? ` · score ${p.securityScore}` : ""}`,
        },
      },
    ],
  };
}

function formatTeams(p: WebhookPayload) {
  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    summary: p.message,
    themeColor: p.event.includes("fail") || p.event === "finding.critical" ? "D13438" : "0078D4",
    title: "Ghoststrike",
    text: p.message,
    sections: [
      {
        facts: [
          { name: "Scan", value: String(p.scanId) },
          ...(p.targetName ? [{ name: "Target", value: p.targetName }] : []),
          ...(p.securityScore != null ? [{ name: "Score", value: String(p.securityScore) }] : []),
          ...(p.riskLevel ? [{ name: "Risk", value: p.riskLevel }] : []),
        ],
      },
    ],
  };
}

export async function dispatchWebhooks(
  config: IntegrationsConfig | null | undefined,
  payload: WebhookPayload
): Promise<{ sent: number; failed: number }> {
  const endpoints = ((config as any)?.webhooks as WebhookEndpoint[] | undefined) || [];

  let sent = 0;
  let failed = 0;
  for (const ep of endpoints) {
    if (!ep.url) continue;
    const events = ep.events?.length ? ep.events : (["scan.completed", "scan.failed", "gate.failed", "finding.critical"] as WebhookEvent[]);
    if (!events.includes(payload.event)) continue;
    try {
      const type = ep.type || "generic";
      const bodyObj =
        type === "slack" ? formatSlack(payload) : type === "teams" ? formatTeams(payload) : payload;
      const body = JSON.stringify(bodyObj);
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "User-Agent": "Ghoststrike-Webhooks/1.0",
        "X-Ghoststrike-Event": payload.event,
      };
      if (ep.secret) headers["X-Ghoststrike-Signature"] = sign(ep.secret, body);
      const res = await fetch(ep.url, {
        method: "POST",
        headers,
        body,
        signal: AbortSignal.timeout(10000),
      });
      if (res.ok) sent++;
      else failed++;
    } catch {
      failed++;
    }
  }

  // Env-configured n8n security alerts (independent of org integration webhooks)
  try {
    const n8n = n8nAlertFromScanEvent({
      event: payload.event,
      message: payload.message,
      scanId: payload.scanId,
      targetUrl: payload.targetUrl,
      riskLevel: payload.riskLevel,
      criticalCount: payload.criticalCount,
      highCount: payload.highCount,
    });
    if (n8n) {
      const ok = await sendN8nSecurityAlert(n8n);
      if (ok) sent++;
      else if (process.env.N8N_WEBHOOK_URL && process.env.N8N_WEBHOOK_TOKEN) failed++;
    }
  } catch {
    failed++;
  }

  return { sent, failed };
}
