/**
 * n8n operations-security-alerts webhook.
 *
 * Env:
 * - N8N_WEBHOOK_URL — e.g. https://…/webhook/operations-security-alerts
 * - N8N_WEBHOOK_TOKEN — value for X-Webhook-Token
 */

export type N8nAlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface N8nSecurityAlert {
  text: string;
  severity: N8nAlertSeverity;
  source?: string;
  title?: string;
}

function configured(): { url: string; token: string } | null {
  const url = (process.env.N8N_WEBHOOK_URL || "").trim();
  const token = (process.env.N8N_WEBHOOK_TOKEN || "").trim();
  if (!url || !token) return null;
  return { url, token };
}

/** POST a security alert to the configured n8n webhook. No-op if env is unset. */
export async function sendN8nSecurityAlert(alert: N8nSecurityAlert): Promise<boolean> {
  const cfg = configured();
  if (!cfg) return false;

  const body = JSON.stringify({
    text: alert.text,
    severity: alert.severity,
    source: alert.source || "ghoststrike",
    title: alert.title || "Security alert",
  });

  try {
    const res = await fetch(cfg.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Webhook-Token": cfg.token,
        "User-Agent": "Ghoststrike-N8n/1.0",
      },
      body,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) {
      console.warn(`[n8n] alert failed: ${res.status} ${res.statusText}`);
      return false;
    }
    return true;
  } catch (err) {
    console.warn(`[n8n] alert error: ${(err as Error).message}`);
    return false;
  }
}

/** Map Ghoststrike webhook events → n8n alert fields */
export function n8nAlertFromScanEvent(input: {
  event: string;
  message: string;
  scanId: number;
  targetUrl?: string;
  riskLevel?: string | null;
  criticalCount?: number;
  highCount?: number;
}): N8nSecurityAlert | null {
  const { event, message, scanId, targetUrl, riskLevel, criticalCount, highCount } = input;
  if (event === "finding.critical" || (event === "scan.completed" && (criticalCount || 0) > 0)) {
    return {
      title: "Critical findings detected",
      text: `${message}${targetUrl ? ` · ${targetUrl}` : ""} (scan #${scanId})`,
      severity: "critical",
      source: "ghoststrike",
    };
  }
  if (event === "scan.failed" || event === "gate.failed") {
    return {
      title: event === "gate.failed" ? "CI security gate failed" : "Scan failed",
      text: `${message}${targetUrl ? ` · ${targetUrl}` : ""} (scan #${scanId})`,
      severity: "high",
      source: "ghoststrike",
    };
  }
  if (event === "scan.completed" && (riskLevel === "high" || riskLevel === "critical" || (highCount || 0) > 0)) {
    return {
      title: "High-risk scan completed",
      text: `${message}${targetUrl ? ` · ${targetUrl}` : ""} (scan #${scanId})`,
      severity: riskLevel === "critical" ? "critical" : "high",
      source: "ghoststrike",
    };
  }
  return null;
}
