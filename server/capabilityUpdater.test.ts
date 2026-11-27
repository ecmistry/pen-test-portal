import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./penTestUpdater", () => ({
  updatePenTestCapabilities: vi.fn(),
}));

import { updatePenTestCapabilities } from "./penTestUpdater";
import {
  clearCapabilityCronGuards,
  cronMatchesUtc,
  DEFAULT_CAPABILITY_CRON,
  getCapabilityUpdaterStatus,
  runCapabilityUpdate,
  shouldRunCapabilityCron,
  startCapabilityUpdater,
  stopCapabilityUpdater,
  tickCapabilityCron,
  utcDayKey,
} from "./capabilityUpdater";

describe("capabilityUpdater", () => {
  beforeEach(() => {
    stopCapabilityUpdater();
    clearCapabilityCronGuards();
    vi.mocked(updatePenTestCapabilities).mockReset();
    delete process.env.CAPABILITY_AUTO_UPDATE;
    delete process.env.CAPABILITY_UPDATE_CRON;
    delete process.env.CAPABILITY_UPDATE_POLL_MS;
  });

  afterEach(() => {
    stopCapabilityUpdater();
    clearCapabilityCronGuards();
  });

  it("DEFAULT_CAPABILITY_CRON is 03:00 UTC daily", () => {
    expect(DEFAULT_CAPABILITY_CRON).toBe("0 0 3 * * *");
  });

  it("cronMatchesUtc matches 03:00:00 UTC", () => {
    const at3am = new Date("2026-11-27T03:00:00.000Z");
    expect(cronMatchesUtc(DEFAULT_CAPABILITY_CRON, at3am)).toBe(true);
    expect(cronMatchesUtc(DEFAULT_CAPABILITY_CRON, new Date("2026-11-27T03:00:30.000Z"))).toBe(false);
    expect(cronMatchesUtc(DEFAULT_CAPABILITY_CRON, new Date("2026-11-27T02:59:00.000Z"))).toBe(false);
  });

  it("shouldRunCapabilityCron dedupes by UTC day", () => {
    const at3am = new Date("2026-11-27T03:00:00.000Z");
    expect(shouldRunCapabilityCron(DEFAULT_CAPABILITY_CRON, at3am, null)).toBe(true);
    expect(shouldRunCapabilityCron(DEFAULT_CAPABILITY_CRON, at3am, "2026-11-27")).toBe(false);
    expect(shouldRunCapabilityCron(DEFAULT_CAPABILITY_CRON, at3am, "2026-11-26")).toBe(true);
  });

  it("runCapabilityUpdate records status from updatePenTestCapabilities", async () => {
    vi.mocked(updatePenTestCapabilities).mockResolvedValueOnce({
      success: true,
      lastUpdated: "2026-11-27T00:00:00.000Z",
      payloads: { sqli: 10, xss: 20 },
      nuclei: { updated: true, version: "3.0.0" },
      nucleiRelease: { tag: "v9.9.0", publishedAt: "2026-11-01T00:00:00Z" },
    });

    const result = await runCapabilityUpdate("manual");
    expect(result.success).toBe(true);
    expect(result.payloads?.sqli).toBe(10);

    const status = getCapabilityUpdaterStatus();
    expect(status.lastTrigger).toBe("manual");
    expect(status.lastSuccess).toBe(true);
    expect(status.cron).toBe(DEFAULT_CAPABILITY_CRON);
    expect(status.timezone).toBe("UTC");
    expect(status.nucleiRelease?.tag).toBe("v9.9.0");
    expect(status.lastRunAt).toBeTruthy();
  });

  it("tickCapabilityCron runs once at 3am UTC and not again same day", async () => {
    vi.mocked(updatePenTestCapabilities).mockResolvedValue({
      success: true,
      lastUpdated: "2026-11-27T03:00:00.000Z",
      payloads: { sqli: 1, xss: 1 },
      nuclei: { updated: true },
    });

    const at3am = new Date("2026-11-27T03:00:00.000Z");
    expect(await tickCapabilityCron(at3am)).toBe(true);
    expect(updatePenTestCapabilities).toHaveBeenCalledTimes(1);
    expect(getCapabilityUpdaterStatus().lastCronDayUtc).toBe(utcDayKey(at3am));

    expect(await tickCapabilityCron(new Date("2026-11-27T03:00:45.000Z"))).toBe(false);
    expect(updatePenTestCapabilities).toHaveBeenCalledTimes(1);

    expect(await tickCapabilityCron(new Date("2026-11-28T03:00:00.000Z"))).toBe(true);
    expect(updatePenTestCapabilities).toHaveBeenCalledTimes(2);
  });

  it("startCapabilityUpdater respects CAPABILITY_AUTO_UPDATE=false", () => {
    process.env.CAPABILITY_AUTO_UPDATE = "false";
    startCapabilityUpdater(1000);
    stopCapabilityUpdater();
    expect(getCapabilityUpdaterStatus().enabled).toBe(false);
  });

  it("startCapabilityUpdater polls and fires when cron matches", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-27T02:59:30.000Z"));
    vi.mocked(updatePenTestCapabilities).mockResolvedValue({
      success: true,
      lastUpdated: "2026-11-27T03:00:00.000Z",
      payloads: { sqli: 1, xss: 1 },
      nuclei: { updated: true },
    });

    startCapabilityUpdater(30_000);
    expect(updatePenTestCapabilities).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(30_000); // 03:00:00 UTC
    expect(updatePenTestCapabilities).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(30_000); // still same UTC day
    expect(updatePenTestCapabilities).toHaveBeenCalledTimes(1);

    stopCapabilityUpdater();
    vi.useRealTimers();
  });
});
