import { describe, expect, it } from "vitest";
import { getSessionCookieOptions } from "./cookies";

describe("getSessionCookieOptions", () => {
  it("sets secure and sameSite none when protocol is https", () => {
    const opts = getSessionCookieOptions({
      protocol: "https",
      headers: {},
    } as any);
    expect(opts.secure).toBe(true);
    expect(opts.sameSite).toBe("none");
    expect(opts.httpOnly).toBe(true);
    expect(opts.path).toBe("/");
  });

  it("sets secure from x-forwarded-proto when protocol is http", () => {
    const opts = getSessionCookieOptions({
      protocol: "http",
      headers: { "x-forwarded-proto": "https" },
    } as any);
    expect(opts.secure).toBe(true);
    expect(opts.sameSite).toBe("none");
  });

  it("sets sameSite lax when not secure", () => {
    const opts = getSessionCookieOptions({
      protocol: "http",
      headers: {},
    } as any);
    expect(opts.secure).toBe(false);
    expect(opts.sameSite).toBe("lax");
  });

  it("treats x-forwarded-proto comma list with https as secure", () => {
    const opts = getSessionCookieOptions({
      protocol: "http",
      headers: { "x-forwarded-proto": "http, https" },
    } as any);
    expect(opts.secure).toBe(true);
  });

  it("treats x-forwarded-proto as array with https as secure", () => {
    const opts = getSessionCookieOptions({
      protocol: "http",
      headers: { "x-forwarded-proto": ["http", "https"] },
    } as any);
    expect(opts.secure).toBe(true);
  });
});
