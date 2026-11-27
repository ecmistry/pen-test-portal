/**
 * Shared GitHub/repo clone helpers for SAST, SCA, and secrets scanning.
 */
import { existsSync, readdirSync, rmSync, statSync, writeFileSync } from "fs";
import { join, basename, relative } from "path";
import { assertSafeOutboundUrl, runTool } from "./netSafety";

export const LOCKFILE_ECOSYSTEM: Record<string, string> = {
  "pom.xml": "Maven",
  "build.gradle": "Maven",
  "build.gradle.kts": "Maven",
  "gradle.lockfile": "Maven",
  "package.json": "npm",
  "package-lock.json": "npm",
  "yarn.lock": "npm",
  "pnpm-lock.yaml": "npm",
  "requirements.txt": "PyPI",
  "Pipfile.lock": "PyPI",
  "poetry.lock": "PyPI",
  "go.mod": "Go",
  "go.sum": "Go",
  "Gemfile.lock": "RubyGems",
  "Cargo.lock": "crates.io",
  "composer.lock": "Packagist",
};

export type RepoCloneOptions = {
  scanId: number;
  repoUrl: string;
  branch?: string | null;
  ref?: string | null;
  /** Relative subpath inside repo to focus scanners on */
  subpath?: string | null;
  /** Explicit token; otherwise env / Integrations UI token is used */
  githubToken?: string | null;
  userId?: number | null;
  orgId?: number | null;
};

export type RepoCloneResult = {
  cloneDir: string;
  scanRoot: string;
  repoUrl: string;
};

/** Env tokens used for private GitHub clones (classic PAT alias supported). */
export function envGithubCloneToken(): string {
  return (
    (process.env.GITHUB_TOKEN || "").trim() ||
    (process.env.GITHUB_CLASSIC_TOKEN || "").trim()
  );
}

/** Build authenticated HTTPS clone URL when a GitHub token is set (github.com only). */
export function withGithubToken(repoUrl: string, token?: string): string {
  const t = (token || envGithubCloneToken()).trim();
  if (!t) return repoUrl;
  try {
    const u = new URL(repoUrl);
    if (!/github\.com$/i.test(u.hostname) && !/\.githubusercontent\.com$/i.test(u.hostname)) return repoUrl;
    // x-access-token for GitHub PATs / fine-grained tokens
    u.username = "x-access-token";
    u.password = t;
    return u.toString();
  } catch {
    return repoUrl;
  }
}

/**
 * Resolve clone token: explicit arg → GITHUB_TOKEN / GITHUB_CLASSIC_TOKEN → Integrations UI.
 */
export async function resolveGithubCloneToken(opts?: {
  token?: string | null;
  userId?: number | null;
  orgId?: number | null;
}): Promise<string> {
  const explicit = (opts?.token || "").trim();
  if (explicit) return explicit;
  const env = envGithubCloneToken();
  if (env) return env;
  if (!opts?.userId && !opts?.orgId) return "";
  try {
    const { getIntegrationForUser } = await import("./db");
    const { decryptIntegrationsConfig } = await import("./integrationsCrypto");
    const row = await getIntegrationForUser(opts.userId || 0, opts.orgId);
    if (!row?.configEnc) return "";
    const cfg = decryptIntegrationsConfig(row.configEnc);
    return (cfg.repoScan?.githubToken || "").trim();
  } catch {
    return "";
  }
}

export function defaultCloneDir(scanId: number): string {
  return `/tmp/repo-scan-${scanId}`;
}

/** Shallow clone (optional branch/ref). Caller must cleanup. */
export async function cloneGitRepo(opts: RepoCloneOptions): Promise<RepoCloneResult> {
  const cloneDir = defaultCloneDir(opts.scanId);
  if (existsSync(cloneDir)) rmSync(cloneDir, { recursive: true, force: true });

  const safeRepo = await assertSafeOutboundUrl(opts.repoUrl, { protocols: ["https:"] });
  const token = await resolveGithubCloneToken({
    token: opts.githubToken,
    userId: opts.userId,
    orgId: opts.orgId,
  });
  const authed = withGithubToken(safeRepo.href, token || undefined);
  // Re-parse after token injection — still https only
  const authedUrl = new URL(authed);
  if (authedUrl.protocol !== "https:") throw new Error("Only https clone URLs are allowed");

  const cloneTimeout = Number(process.env.SAST_CLONE_TIMEOUT_MS || 180000);
  const args = [
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "clone",
    "--depth", "1",
  ];
  const branch = (opts.branch || opts.ref || "").trim();
  if (branch) {
    args.push("--branch", branch);
  } else {
    args.push("--single-branch");
  }
  args.push("--", authedUrl.toString(), cloneDir);

  const clone = await runTool("git", args, {
    timeout: Number.isFinite(cloneTimeout) ? cloneTimeout : 180000,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ALLOW_PROTOCOL: "https" },
  });
  if (clone.code !== 0) {
    throw new Error(`git clone failed: ${(clone.stderr || clone.stdout || "").substring(0, 300)}`);
  }

  let scanRoot = cloneDir;
  const sub = (opts.subpath || "").replace(/^\/+/, "").replace(/\.\./g, "");
  if (sub) {
    const candidate = join(cloneDir, sub);
    if (existsSync(candidate) && statSync(candidate).isDirectory()) {
      scanRoot = candidate;
    }
  }

  return { cloneDir, scanRoot, repoUrl: opts.repoUrl };
}

export function cleanupClone(cloneDir: string): void {
  try {
    if (existsSync(cloneDir)) rmSync(cloneDir, { recursive: true, force: true });
  } catch { /* best-effort */ }
}

/** Walk tree for known lockfiles/manifests (budgeted). Prefer lockfiles over package.json. */
export function discoverLockfiles(root: string, budget = 40): Array<{ path: string; name: string; ecosystem: string }> {
  const out: Array<{ path: string; name: string; ecosystem: string }> = [];
  const skip = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".gradle", "coverage", "__pycache__"]);
  const prefer = new Set([
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pom.xml", "gradle.lockfile",
    "Pipfile.lock", "poetry.lock", "go.sum", "Gemfile.lock", "Cargo.lock", "composer.lock",
  ]);

  function walk(dir: string, depth: number) {
    if (out.length >= budget || depth > 6) return;
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (skip.has(name) || name.startsWith(".")) continue;
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        walk(full, depth + 1);
      } else if (LOCKFILE_ECOSYSTEM[name]) {
        // Prefer real lockfiles; still accept package.json / go.mod if no lock nearby later
        out.push({ path: full, name, ecosystem: LOCKFILE_ECOSYSTEM[name] });
        if (out.length >= budget) return;
      }
    }
  }
  walk(root, 0);

  // Prefer lockfiles over package.json when both exist in same dir
  const byDir = new Map<string, typeof out>();
  for (const item of out) {
    const dir = item.path.slice(0, item.path.length - item.name.length);
    const list = byDir.get(dir) ?? [];
    list.push(item);
    byDir.set(dir, list);
  }
  const filtered: typeof out = [];
  for (const list of Array.from(byDir.values())) {
    const locks = list.filter((i) => prefer.has(i.name));
    if (locks.length) filtered.push(...locks);
    else filtered.push(...list);
  }
  return filtered.slice(0, budget);
}

export function semgrepConfigs(): string[] {
  const raw = (process.env.SEMGREP_CONFIG || "p/owasp-top-ten,p/java,p/javascript,p/typescript,p/secrets").trim();
  const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
  return parts.length ? parts : ["auto"];
}

export function semgrepExcludeGlobs(): string[] {
  const raw = process.env.SEMGREP_EXCLUDE ||
    "node_modules,dist,build,target,.git,coverage,vendor,**/*Test.java,**/test/**,**/tests/**,**/*.min.js";
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

/** Build Semgrep CLI args for a scan root */
export function buildSemgrepArgs(scanRoot: string): string[] {
  const args: string[] = ["--json", "--severity", "WARNING", "--severity", "ERROR", "--timeout", "30"];
  for (const cfg of semgrepConfigs()) {
    args.push("--config", cfg);
  }
  for (const ex of semgrepExcludeGlobs()) {
    args.push("--exclude", ex);
  }
  args.push("--", scanRoot);
  return args;
}

/** Severity rank for sorting Semgrep / SCA results */
export function severityRank(sev: string): number {
  const s = sev.toUpperCase();
  if (s === "ERROR" || s === "CRITICAL") return 4;
  if (s === "WARNING" || s === "HIGH") return 3;
  if (s === "MEDIUM") return 2;
  if (s === "INFO" || s === "LOW") return 1;
  return 0;
}

/** Persist scanner JSON under /tmp and return path (caller may copy to artifact store) */
export function writeScanArtifact(scanId: number, tool: string, content: string): string {
  const p = `/tmp/ghoststrike-${tool}-${scanId}.json`;
  writeFileSync(p, content, "utf8");
  return p;
}

export function relativeRepoPath(cloneDir: string, absPath: string): string {
  return relative(cloneDir, absPath).replace(/\\/g, "/") || basename(absPath);
}
