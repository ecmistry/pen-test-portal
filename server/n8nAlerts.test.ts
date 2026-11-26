import { afterEach, describe, expect, it, vi } from "vitest";
import { n8nAlertFromScanEvent, sendN8nSecurityAlert } from "./n8nAlerts";

describe("n8nAlertFromScanEvent", () => {
  it("maps critical findings", () => {
    const a = n8nAlertFromScanEvent({
      event: "finding.critical",
      message: "2 critical",
      scanId: 9,
      targetUrl: "https://t",
      criticalCount: 2,
    });
    expect(a?.severity).toBe("critical");
    expect(a?.source).toBe("ghoststrike");
    expect(a?.text).toContain("https://t");
  });

  it("maps scan failed to high", () => {
    const a = n8nAlertFromScanEvent({
      event: "scan.failed",
      message: "timeout",
      scanId: 1,
    });
    expect(a?.severity).toBe("high");
    expect(a?.title).toMatch(/failed/i);
  });

  it("skips quiet completed scans", () => {
    expect(
      n8nAlertFromScanEvent({
        event: "scan.completed",
        message: "ok",
        scanId: 1,
        riskLevel: "low",
        criticalCount: 0,
        highCount: 0,
      })
    ).toBeNull();
  });
});

describe("sendN8nSecurityAlert", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.N8N_WEBHOOK_URL;
    delete process.env.N8N_WEBHOOK_TOKEN;
  });

  it("no-ops when env missing", async () => {
    delete process.env.N8N_WEBHOOK_URL;
    delete process.env.N8N_WEBHOOK_TOKEN;
    expect(await sendN8nSecurityAlert({ text: "x", severity: "high" })).toBe(false);
  });

  it("posts with X-Webhook-Token", async () => {
    process.env.N8N_WEBHOOK_URL = "https://example.test/webhook/ops";
    process.env.N8N_WEBHOOK_TOKEN = "secret-token";
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, statusText: "OK" });
    vi.stubGlobal("fetch", fetchMock);

    const ok = await sendN8nSecurityAlert({
      text: "Suspicious login from unknown IP",
      severity: "high",
      source: "ghoststrike",
      title: "Security alert",
    });
    expect(ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://example.test/webhook/ops");
    expect(init.method).toBe("POST");
    expect(init.headers["X-Webhook-Token"]).toBe("secret-token");
    expect(JSON.parse(init.body)).toEqual({
      text: "Suspicious login from unknown IP",
      severity: "high",
      source: "ghoststrike",
      title: "Security alert",
    });
  });
});
