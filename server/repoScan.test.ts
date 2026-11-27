import { describe, expect, it } from "vitest";
import {
  withGithubToken,
  resolveGithubCloneToken,
  discoverLockfiles,
  buildSemgrepArgs,
  severityRank,
  LOCKFILE_ECOSYSTEM,
} from "./repoScan";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("withGithubToken", () => {
  it("injects token for github.com HTTPS URLs", () => {
    const out = withGithubToken("https://github.com/org/repo.git", "tok123");
    expect(out).toContain("x-access-token");
    expect(out).toContain("tok123");
    expect(out).toContain("github.com/org/repo.git");
  });

  it("leaves non-github URLs alone", () => {
    expect(withGithubToken("https://gitlab.com/a/b.git", "tok")).toBe("https://gitlab.com/a/b.git");
  });
});

describe("resolveGithubCloneToken", () => {
  it("prefers explicit token over env", async () => {
    const prev = process.env.GITHUB_TOKEN;
    const prevClassic = process.env.GITHUB_CLASSIC_TOKEN;
    process.env.GITHUB_TOKEN = "env-tok";
    delete process.env.GITHUB_CLASSIC_TOKEN;
    try {
      expect(await resolveGithubCloneToken({ token: "ui-tok" })).toBe("ui-tok");
      expect(await resolveGithubCloneToken({})).toBe("env-tok");
    } finally {
      if (prev === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = prev;
      if (prevClassic === undefined) delete process.env.GITHUB_CLASSIC_TOKEN;
      else process.env.GITHUB_CLASSIC_TOKEN = prevClassic;
    }
  });

  it("falls back to GITHUB_CLASSIC_TOKEN", async () => {
    const prev = process.env.GITHUB_TOKEN;
    const prevClassic = process.env.GITHUB_CLASSIC_TOKEN;
    delete process.env.GITHUB_TOKEN;
    process.env.GITHUB_CLASSIC_TOKEN = "classic-tok";
    try {
      expect(await resolveGithubCloneToken({})).toBe("classic-tok");
    } finally {
      if (prev === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = prev;
      if (prevClassic === undefined) delete process.env.GITHUB_CLASSIC_TOKEN;
      else process.env.GITHUB_CLASSIC_TOKEN = prevClassic;
    }
  });
});

describe("discoverLockfiles", () => {
  it("finds lockfiles and prefers them over package.json", () => {
    const root = mkdtempSync(join(tmpdir(), "gs-locks-"));
    try {
      mkdirSync(join(root, "svc"));
      writeFileSync(join(root, "svc", "package.json"), "{}");
      writeFileSync(join(root, "svc", "package-lock.json"), "{}");
      writeFileSync(join(root, "pom.xml"), "<project/>");
      const found = discoverLockfiles(root, 20);
      expect(found.some((f) => f.name === "pom.xml")).toBe(true);
      expect(found.some((f) => f.name === "package-lock.json")).toBe(true);
      expect(found.some((f) => f.name === "package.json")).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("buildSemgrepArgs", () => {
  it("includes configs and excludes", () => {
    const args = buildSemgrepArgs("/tmp/repo");
    expect(args).toContain("--config");
    expect(args).toContain("--exclude");
    expect(args[args.length - 1]).toBe("/tmp/repo");
  });
});

describe("LOCKFILE_ECOSYSTEM", () => {
  it("covers yarn/pnpm/gradle/cargo", () => {
    expect(LOCKFILE_ECOSYSTEM["yarn.lock"]).toBe("npm");
    expect(LOCKFILE_ECOSYSTEM["pnpm-lock.yaml"]).toBe("npm");
    expect(LOCKFILE_ECOSYSTEM["Cargo.lock"]).toBe("crates.io");
    expect(severityRank("CRITICAL")).toBeGreaterThan(severityRank("LOW"));
  });
});
