import { describe, expect, it, beforeEach } from "vitest";
import {
  clearRunningScheduleGuards,
  cronMatches,
  matchCronField,
  shouldRunSchedule,
} from "./scheduleRunner";

describe("matchCronField", () => {
  it("matches star", () => {
    expect(matchCronField("*", 5)).toBe(true);
  });

  it("matches exact value", () => {
    expect(matchCronField("9", 9)).toBe(true);
    expect(matchCronField("9", 8)).toBe(false);
  });

  it("matches lists and ranges", () => {
    expect(matchCronField("1,5,9", 5)).toBe(true);
    expect(matchCronField("1-3", 2)).toBe(true);
    expect(matchCronField("1-3", 4)).toBe(false);
  });

  it("matches step expressions", () => {
    expect(matchCronField("*/15", 0)).toBe(true);
    expect(matchCronField("*/15", 15)).toBe(true);
    expect(matchCronField("*/15", 16)).toBe(false);
    expect(matchCronField("10-50/10", 20)).toBe(true);
  });
});

describe("cronMatches", () => {
  it("requires 6 fields", () => {
    expect(cronMatches("0 * * * *")).toBe(false);
  });

  it("matches a concrete datetime", () => {
    // Monday 2026-11-23 09:00:00 local
    const d = new Date(2026, 10, 23, 9, 0, 0);
    expect(cronMatches("0 0 9 * * 1", d)).toBe(true);
    expect(cronMatches("0 0 9 * * 2", d)).toBe(false);
  });
});

describe("shouldRunSchedule", () => {
  beforeEach(() => clearRunningScheduleGuards());

  it("skips disabled schedules", () => {
    const now = new Date(2026, 10, 23, 9, 0, 0);
    expect(
      shouldRunSchedule(
        { enabled: false, cronExpression: "0 0 9 * * 1", lastRunAt: null },
        now
      )
    ).toBe(false);
  });

  it("prevents double-fire in the same minute", () => {
    const now = new Date(2026, 10, 23, 9, 0, 30);
    expect(
      shouldRunSchedule(
        { enabled: true, cronExpression: "0 0 9 * * 1", lastRunAt: new Date(2026, 10, 23, 9, 0, 5) },
        now
      )
    ).toBe(false);
  });

  it("allows run when cron matches and last run was earlier", () => {
    const now = new Date(2026, 10, 23, 9, 0, 0);
    expect(
      shouldRunSchedule(
        { enabled: true, cronExpression: "0 0 9 * * 1", lastRunAt: new Date(2026, 10, 16, 9, 0, 0) },
        now
      )
    ).toBe(true);
  });
});
