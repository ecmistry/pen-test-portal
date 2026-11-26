import { afterEach, describe, expect, it } from "vitest";
import { assertHostAllowed, assertSafeOutboundUrl, isHttpUrl, isPrivateAddress, runTool, safeLookup } from "./netSafety";

afterEach(() => {
  delete process.env.ALLOW_PRIVATE_TARGETS;
});

describe("isPrivateAddress", () => {
  it.each([
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.33.84", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "fd00:ec2::254",
  ])("blocks %s", (ip) => {
    expect(isPrivateAddress(ip)).toBe(true);
  });

  it.each(["8.8.8.8", "35.177.57.9", "2606:4700:4700::1111"])("allows public %s", (ip) => {
    expect(isPrivateAddress(ip)).toBe(false);
  });
});

describe("isHttpUrl", () => {
  it("accepts http and https", () => {
    expect(isHttpUrl("https://example.com/a")).toBe(true);
    expect(isHttpUrl("http://example.com")).toBe(true);
  });

  it("rejects other schemes and embedded credentials", () => {
    expect(isHttpUrl("file:///etc/passwd")).toBe(false);
    expect(isHttpUrl("ftp://example.com")).toBe(false);
    expect(isHttpUrl("https://u:p@example.com")).toBe(false);
    expect(isHttpUrl("not a url")).toBe(false);
  });
});

describe("assertSafeOutboundUrl", () => {
  it("rejects metadata, loopback and localhost targets", async () => {
    await expect(assertSafeOutboundUrl("http://169.254.169.254/latest/meta-data/")).rejects.toThrow();
    await expect(assertSafeOutboundUrl("http://127.0.0.1:3306")).rejects.toThrow();
    await expect(assertSafeOutboundUrl("http://localhost:3000")).rejects.toThrow();
    await expect(assertSafeOutboundUrl("http://[::1]/")).rejects.toThrow();
  });

  it("enforces the allowed protocol list", async () => {
    await expect(assertSafeOutboundUrl("http://8.8.8.8/", { protocols: ["https:"] })).rejects.toThrow(/scheme/);
  });

  it("allows public IP literals", async () => {
    await expect(assertSafeOutboundUrl("https://8.8.8.8/")).resolves.toBeInstanceOf(URL);
  });

  it("allows private targets only when ALLOW_PRIVATE_TARGETS=true", async () => {
    process.env.ALLOW_PRIVATE_TARGETS = "true";
    await expect(assertSafeOutboundUrl("http://10.0.0.5/")).resolves.toBeInstanceOf(URL);
  });
});

describe("runTool", () => {
  it("passes arguments literally without a shell", async () => {
    const payload = "https://x.test/$(echo pwned);echo injected";
    const { stdout, code } = await runTool("echo", [payload]);
    expect(code).toBe(0);
    expect(stdout.trim()).toBe(payload);
  });

  it("resolves with a non-zero code instead of rejecting", async () => {
    const { code } = await runTool("false", []);
    expect(code).not.toBe(0);
  });

  it("rejects when the executable does not exist", async () => {
    await expect(runTool("definitely-not-a-real-binary-xyz", [])).rejects.toThrow();
  });
});

describe("safeLookup / assertHostAllowed", () => {
  const lookupAsync = (host: string) =>
    new Promise<string>((resolve, reject) =>
      safeLookup(host, {}, (err, address) => (err ? reject(err) : resolve(address as string)))
    );

  it("refuses hostnames that resolve to loopback", async () => {
    await expect(lookupAsync("localhost")).rejects.toThrow(/internal address/);
  });

  it("resolves public hostnames", async () => {
    await expect(lookupAsync("example.com")).resolves.toMatch(/\d|:/);
  });

  it("blocks private IP literals", () => {
    expect(() => assertHostAllowed("169.254.169.254")).toThrow();
    expect(() => assertHostAllowed("[::1]")).toThrow();
    expect(() => assertHostAllowed("8.8.8.8")).not.toThrow();
    expect(() => assertHostAllowed("example.com")).not.toThrow();
  });
});
