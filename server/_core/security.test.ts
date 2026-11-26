import { afterEach, describe, expect, it } from "vitest";
import { ENV } from "./env";
import { assertSecureConfig, safeEqual } from "./security";

const original = { ...ENV };

afterEach(() => {
  Object.assign(ENV, original);
});

describe("safeEqual", () => {
  it("returns true for identical strings", () => {
    expect(safeEqual("secret-value", "secret-value")).toBe(true);
  });

  it("returns false for different strings, including different lengths", () => {
    expect(safeEqual("secret-value", "secret-valuf")).toBe(false);
    expect(safeEqual("short", "much-longer-value")).toBe(false);
    expect(safeEqual("", "x")).toBe(false);
  });
});

describe("assertSecureConfig", () => {
  it("does nothing outside production", () => {
    Object.assign(ENV, { isProduction: false, cookieSecret: "", devBypassAuth: true });
    expect(() => assertSecureConfig()).not.toThrow();
  });

  it("rejects a short JWT_SECRET in production", () => {
    Object.assign(ENV, { isProduction: true, cookieSecret: "too-short", devBypassAuth: false });
    expect(() => assertSecureConfig()).toThrow(/JWT_SECRET/);
  });

  it("rejects DEV_BYPASS_AUTH in production", () => {
    Object.assign(ENV, { isProduction: true, cookieSecret: "x".repeat(64), devBypassAuth: true });
    expect(() => assertSecureConfig()).toThrow(/DEV_BYPASS_AUTH/);
  });

  it("accepts a strong secret with dev bypass off in production", () => {
    Object.assign(ENV, { isProduction: true, cookieSecret: "x".repeat(64), devBypassAuth: false });
    expect(() => assertSecureConfig()).not.toThrow();
  });
});
