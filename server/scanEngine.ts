/**
 * Scan Engine — executes security tests against a target URL.
 *
 * Scan modes:
 *   light — Quick scan: limited payloads, ~40–60 requests, completes in seconds
 *   full  — Comprehensive pen test: OWASP-aligned, extended payloads, time-based checks,
 *           CORS, directory traversal, backup files, external tools (nikto/nuclei/zap)
 *
 * Supported tools:
 *   headers  — HTTP security headers check (built-in)
 *   auth     — Authentication security checks (built-in)
 *   sqli     — SQL injection probes (built-in)
 *   xss      — Cross-site scripting probes (built-in)
 *   recon    — Intelligence gathering / sensitive path enumeration (built-in)
 *   cors     — CORS misconfiguration (full mode only)
 *   traversal — Directory traversal (full mode only)
 *   config   — Backup files, deployment config (full mode only)
 *   logic    — Business logic tests: debug endpoints, CSRF, mass assignment, stack traces (full mode only)
 *   graphql  — GraphQL endpoint detection, introspection, batch abuse, injection (full mode only)
 *   ssrf     — Server-Side Request Forgery probe via URL/redirect/callback parameter injection (full mode only)
 *   tls      — SSL/TLS certificate and cipher analysis (full mode only, optional testssl.sh)
 *   auth-roles — Authenticated multi-role scanning: vertical/horizontal escalation, session handling (full mode only, requires authProfiles)
 *   sca      — Dependency/SCA scanning via OSV-Scanner or Trivy (full mode only, requires --deps manifest path)
 *   nikto    — Nikto web server scanner (requires nikto installed)
 *   nuclei   — Nuclei vulnerability scanner (requires nuclei installed)
 *   wapiti   — Wapiti black-box scanner, full mode only (optional; pip install wapiti3)
 *   zap      — OWASP ZAP baseline scan (requires zap.sh installed)
 */

import https from "https";
import http from "http";
import { URL } from "url";
import { exec as execCb } from "child_process";
import { promisify } from "util";
import { appendScanLog, createFindings, updateScan, updateTarget, getPreviousCompletedScan, getFindingsByScan } from "./db";

const execAsync = promisify(execCb);

/** Run a command and always resolve with { stdout, stderr, code }; never reject on non-zero exit (so we can capture scanner output). */
function execCapture(
  command: string,
  options: { timeout?: number; encoding?: BufferEncoding; maxBuffer?: number; env?: NodeJS.ProcessEnv }
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    execCb(command, options, (err, stdout, stderr) => {
      if (err && err.code === undefined && err.signal === undefined) {
        reject(err);
        return;
      }
      resolve({
        stdout: typeof stdout === "string" ? stdout : String(stdout ?? ""),
        stderr: typeof stderr === "string" ? stderr : String(stderr ?? ""),
        code: err ? (err as { code?: number }).code ?? 1 : 0,
      });
    });
  });
}
import { InsertScanFinding } from "../drizzle/schema";
import { getPenTestCache } from "./penTestUpdater";
import { enrichFinding } from "./findingEnrichment";

// ─── Types ────────────────────────────────────────────────────────────────────
export type ScanMode = "light" | "full";

interface Finding {
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description?: string;
  evidence?: string;
  recommendation?: string;
  cweId?: string;
  owaspCategory?: string;
  /** Structured proof-of-concept for reproducibility */
  poc?: {
    curlCommand: string;
    requestRaw: string;
    responseSnippet: string;
    reproductionSteps: string[];
  };
  /** Auth-scanning metadata: the role that discovered the issue */
  discoveredAs?: string;
  /** Auth-scanning metadata: the role that can exploit the issue */
  exploitableAs?: string;
  /** Auth-scanning metadata: the minimum privilege level that should be required */
  requiredLevel?: string;
  /** Auth-scanning metadata: the endpoint tested */
  authEndpoint?: string;
}

// ─── Auth Profile Types ──────────────────────────────────────────────────────

export interface AuthProfile {
  name: string;
  type: "none" | "bearer" | "basic";
  token?: string;
  username?: string;
  password?: string;
}

export interface AuthTestConfig {
  verticalEscalation?: boolean;
  horizontalEscalation?: boolean;
  sessionExpiry?: boolean;
  tokenReuse?: boolean;
}

export interface AuthScanConfig {
  authProfiles?: AuthProfile[];
  authTests?: AuthTestConfig;
}

/** Build Authorization header from a profile */
export function buildAuthHeader(profile: AuthProfile): Record<string, string> {
  switch (profile.type) {
    case "bearer":
      return profile.token ? { Authorization: `Bearer ${profile.token}` } : {};
    case "basic": {
      if (!profile.username) return {};
      const encoded = Buffer.from(`${profile.username}:${profile.password ?? ""}`).toString("base64");
      return { Authorization: `Basic ${encoded}` };
    }
    default:
      return {};
  }
}

/** Determine the privilege rank for ordering: higher = more privileged */
export function profilePrivilegeRank(profile: AuthProfile): number {
  const name = profile.name.toLowerCase();
  if (name === "anonymous" || profile.type === "none") return 0;
  if (name.includes("read") || name.includes("viewer")) return 1;
  if (name.includes("standard") || name.includes("user") || name.includes("member")) return 2;
  if (name.includes("editor") || name.includes("manager")) return 3;
  if (name.includes("admin") || name.includes("superadmin") || name.includes("root")) return 4;
  return 2; // default to standard user level
}

type LogLevel = "info" | "warn" | "error" | "success" | "debug";

// ─── Helpers ──────────────────────────────────────────────────────────────────
async function log(scanId: number, level: LogLevel, message: string, phase?: string) {
  await appendScanLog({ scanId, level, message, phase });
}

async function httpGet(
  targetUrl: string,
  path = "/",
  options: { method?: string; body?: string; headers?: Record<string, string>; timeout?: number } = {}
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(path.startsWith("http") ? path : targetUrl + path);
    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || "GET",
      headers: {
        "User-Agent": "PenTestPortal/1.0 Security Scanner",
        "Accept": "text/html,application/json,*/*",
        ...options.headers,
      },
      timeout: options.timeout ?? 10000,
      rejectUnauthorized: false,
    };

    const req = lib.request(reqOptions, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode || 0,
          headers: res.headers as Record<string, string>,
          body,
        });
      });
    });

    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")); });

    if (options.body) req.write(options.body);
    req.end();
  });
}

// ─── Security Headers Test ────────────────────────────────────────────────────
async function testSecurityHeaders(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing security headers for ${targetUrl}`, "headers");

  try {
    const { headers, status } = await httpGet(targetUrl);
    await log(scanId, "info", `Response status: ${status}`, "headers");

    const requiredHeaders: Array<{
      name: string;
      key: string;
      severity: Finding["severity"];
      cwe: string;
      owasp: string;
      recommendation: string;
    }> = [
      {
        name: "Content-Security-Policy",
        key: "content-security-policy",
        severity: "high",
        cwe: "CWE-693",
        owasp: "A05:2021 – Security Misconfiguration",
        recommendation: "Add a Content-Security-Policy header to prevent XSS and data injection attacks.",
      },
      {
        name: "X-Frame-Options",
        key: "x-frame-options",
        severity: "medium",
        cwe: "CWE-1021",
        owasp: "A05:2021 – Security Misconfiguration",
        recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
      },
      {
        name: "X-Content-Type-Options",
        key: "x-content-type-options",
        severity: "medium",
        cwe: "CWE-693",
        owasp: "A05:2021 – Security Misconfiguration",
        recommendation: "Set X-Content-Type-Options: nosniff to prevent MIME type sniffing.",
      },
      {
        name: "Strict-Transport-Security",
        key: "strict-transport-security",
        severity: "high",
        cwe: "CWE-311",
        owasp: "A02:2021 – Cryptographic Failures",
        recommendation: "Add Strict-Transport-Security header to enforce HTTPS.",
      },
      {
        name: "Referrer-Policy",
        key: "referrer-policy",
        severity: "low",
        cwe: "CWE-200",
        owasp: "A05:2021 – Security Misconfiguration",
        recommendation: "Set Referrer-Policy to control referrer information leakage.",
      },
      {
        name: "Permissions-Policy",
        key: "permissions-policy",
        severity: "low",
        cwe: "CWE-693",
        owasp: "A05:2021 – Security Misconfiguration",
        recommendation: "Add Permissions-Policy header to restrict browser feature access.",
      },
    ];

    for (const h of requiredHeaders) {
      const value = headers[h.key];
      if (!value) {
        findings.push({
          category: "Security Headers",
          severity: h.severity,
          title: `Missing ${h.name} header`,
          description: `The ${h.name} HTTP security header is not present in the server response.`,
          evidence: `Header '${h.key}' not found in response headers`,
          recommendation: h.recommendation,
          cweId: h.cwe,
          owaspCategory: h.owasp,
        });
        await log(scanId, "warn", `MISSING: ${h.name}`, "headers");
      } else {
        await log(scanId, "success", `PRESENT: ${h.name}: ${value.substring(0, 80)}`, "headers");

        // Check CSP for unsafe directives (differentiate script-src vs style-src-attr)
        if (h.key === "content-security-policy") {
          const cspLower = value.toLowerCase();
          const hasScriptUnsafe = /script-src[^;]*'unsafe-inline'|script-src[^;]*'unsafe-eval'/.test(cspLower);
          const hasStyleAttrUnsafe = /style-src-attr[^;]*'unsafe-inline'/.test(cspLower);
          const hasStyleSrcUnsafe = /style-src[^;]*'unsafe-inline'/.test(cspLower);
          const scriptUsesNonce = /script-src[^;]*'nonce-|script-src[^;]*'sha256-/.test(cspLower);

          if (hasScriptUnsafe) {
            findings.push({
              category: "Security Headers",
              severity: "high",
              title: "Content-Security-Policy script-src contains unsafe directives",
              description: "script-src contains 'unsafe-inline' or 'unsafe-eval', enabling script injection and XSS.",
              evidence: `CSP value: ${value.substring(0, 200)}`,
              recommendation: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. Use nonces or hashes instead.",
              cweId: "CWE-693",
              owaspCategory: "A05:2021 – Security Misconfiguration",
            });
          } else if (scriptUsesNonce) {
            // Strong script protection; style exceptions are lower risk — skip or downgrade
          } else if (hasStyleAttrUnsafe) {
            findings.push({
              category: "Security Headers",
              severity: "low",
              title: "Content-Security-Policy style-src-attr contains unsafe-inline",
              description: "style-src-attr allows inline styles. Script execution is protected; style injection only. Some third-party widgets require this.",
              evidence: `CSP value: ${value.substring(0, 200)}`,
              recommendation: "Use nonces for style-src-elem where possible. style-src-attr 'unsafe-inline' may be required by widgets.",
              cweId: "CWE-693",
              owaspCategory: "A05:2021 – Security Misconfiguration",
            });
          } else if (hasStyleSrcUnsafe) {
            findings.push({
              category: "Security Headers",
              severity: "low",
              title: "Content-Security-Policy style-src contains unsafe-inline",
              description: "style-src allows inline styles. Script execution is protected; this is lower risk.",
              evidence: `CSP value: ${value.substring(0, 200)}`,
              recommendation: "Consider using nonces for style-src-elem. style-src-attr 'unsafe-inline' may be required by some widgets.",
              cweId: "CWE-693",
              owaspCategory: "A05:2021 – Security Misconfiguration",
            });
          }
        }
      }
    }

    // Check for server information disclosure
    const serverHeader = headers["server"];
    if (serverHeader && /[0-9]/.test(serverHeader)) {
      findings.push({
        category: "Information Disclosure",
        severity: "low",
        title: "Server version information disclosed",
        description: "The Server header reveals version information that could aid attackers.",
        evidence: `Server: ${serverHeader}`,
        recommendation: "Configure the server to suppress or genericise the Server header.",
        cweId: "CWE-200",
        owaspCategory: "A05:2021 – Security Misconfiguration",
      });
    }

    await log(scanId, "success", `Security headers scan complete. Found ${findings.length} issue(s).`, "headers");
  } catch (err: any) {
    await log(scanId, "error", `Headers test failed: ${err.message}`, "headers");
    findings.push({
      category: "Connectivity",
      severity: "info",
      title: "Could not reach target for header inspection",
      description: `The scanner could not connect to the target: ${err.message}`,
      recommendation: "Ensure the target URL is accessible from the scanner.",
    });
  }

  return findings;
}

// ─── Authentication Security Test ─────────────────────────────────────────────
type LoginConfig = { path: string; bodyFn: (email: string, password: string) => string };

const LOGIN_CONFIGS: LoginConfig[] = [
  { path: "/api/trpc/auth.login", bodyFn: (e, p) => JSON.stringify({ json: { email: e, password: p } }) },
  { path: "/api/trpc/auth.login/mutate", bodyFn: (e, p) => JSON.stringify({ json: { email: e, password: p } }) },
  { path: "/api/auth/login", bodyFn: (e, p) => JSON.stringify({ email: e, password: p }) },
  { path: "/api/login", bodyFn: (e, p) => JSON.stringify({ email: e, password: p }) },
  { path: "/login", bodyFn: (e, p) => JSON.stringify({ email: e, password: p }) },
  { path: "/auth/login", bodyFn: (e, p) => JSON.stringify({ email: e, password: p }) },
];

function isRateLimited(resp: { status: number; headers: Record<string, string>; body: string }): boolean {
  if (resp.status === 429) return true;
  const h = resp.headers;
  const v = (k: string) => { const x = h[k]; return Array.isArray(x) ? x[0] : x; };
  if (v("retry-after") || v("x-ratelimit-remaining") === "0") return true;
  const body = resp.body.toLowerCase();
  return body.includes("locked") || body.includes("too many") || body.includes("rate limit");
}

async function testAuthentication(scanId: number, targetUrl: string, scanMode: ScanMode): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing authentication security for ${targetUrl}`, "auth");

  // Discovery: find a working login endpoint
  let loginConfig: LoginConfig | null = null;
  for (const cfg of LOGIN_CONFIGS) {
    try {
      const { status } = await httpGet(targetUrl, cfg.path, {
        method: "POST",
        body: cfg.bodyFn("test@example.com", "wrong"),
        headers: { "Content-Type": "application/json" },
      });
      if (status < 500) {
        loginConfig = cfg;
        await log(scanId, "info", `Found login endpoint: ${cfg.path} (${status})`, "auth");
        break;
      }
    } catch {
      // continue
    }
  }

  const testEndpoint = loginConfig?.path ?? "/api/auth/login";
  const bodyFn = loginConfig?.bodyFn ?? ((e, p) => JSON.stringify({ email: e, password: p }));

  if (!loginConfig) {
    await log(scanId, "info", "No standard login endpoint found — testing generic auth patterns", "auth");
  }

  // Test for account enumeration
  try {
    const validResp = await httpGet(targetUrl, testEndpoint, {
      method: "POST",
      body: bodyFn("valid@example.com", "wrongpassword"),
      headers: { "Content-Type": "application/json" },
    });
    const invalidResp = await httpGet(targetUrl, testEndpoint, {
      method: "POST",
      body: bodyFn("nonexistent@example.com", "wrongpassword"),
      headers: { "Content-Type": "application/json" },
    });

    if (validResp.body !== invalidResp.body && validResp.status !== invalidResp.status) {
      findings.push({
        category: "Authentication",
        severity: "medium",
        title: "Potential account enumeration vulnerability",
        description: "Different responses for valid vs invalid email addresses may allow attackers to enumerate valid accounts.",
        evidence: `Valid email response (${validResp.status}): ${validResp.body.substring(0, 100)}\nInvalid email response (${invalidResp.status}): ${invalidResp.body.substring(0, 100)}`,
        recommendation: "Return identical error messages and status codes for both valid and invalid credentials.",
        cweId: "CWE-203",
        owaspCategory: "A07:2021 – Identification and Authentication Failures",
      });
      await log(scanId, "warn", "Potential account enumeration detected", "auth");
    } else {
      await log(scanId, "success", "Account enumeration protection: PASS", "auth");
    }
  } catch (err: any) {
    await log(scanId, "info", `Auth enumeration test skipped: ${err.message}`, "auth");
  }

  // Test for brute force protection (check headers: 429, Retry-After, X-RateLimit-Remaining)
  const bruteForceAttempts = scanMode === "full" ? 12 : 6;
  try {
    let lockedOut = false;
    for (let i = 0; i < bruteForceAttempts; i++) {
      const resp = await httpGet(targetUrl, testEndpoint, {
        method: "POST",
        body: bodyFn("test@example.com", `wrongpass${i}`),
        headers: { "Content-Type": "application/json" },
      });
      if (isRateLimited(resp)) {
        lockedOut = true;
        await log(scanId, "success", `Brute force protection triggered after ${i + 1} attempts (429/Retry-After/rate-limit)`, "auth");
        break;
      }
    }
    if (!lockedOut) {
      findings.push({
        category: "Authentication",
        severity: "high",
        title: "No brute force protection detected",
        description: "The application does not appear to lock accounts or rate-limit after multiple failed login attempts.",
        evidence: `${bruteForceAttempts} consecutive failed login attempts did not trigger lockout or rate limiting (no 429, Retry-After, or X-RateLimit-Remaining: 0)`,
        recommendation: "Implement account lockout after 3-5 failed attempts, rate limiting (e.g. 5 attempts per 15 minutes), and consider CAPTCHA.",
        cweId: "CWE-307",
        owaspCategory: "A07:2021 – Identification and Authentication Failures",
      });
      await log(scanId, "warn", "No brute force protection detected", "auth");
    }
  } catch (err: any) {
    await log(scanId, "info", `Brute force test skipped: ${err.message}`, "auth");
  }

  await log(scanId, "success", `Authentication scan complete. Found ${findings.length} issue(s).`, "auth");
  return findings;
}

// ─── SQL Injection Test ───────────────────────────────────────────────────────
const SQLI_PAYLOADS_LIGHT = [
  "' OR '1'='1",
  "' OR 1=1--",
];

const SQLI_PAYLOADS_FULL = [
  "' OR '1'='1",
  "' OR 1=1--",
  "'; DROP TABLE users;--",
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT @@version,NULL,NULL--",
  "1' AND '1'='1",
  "1' AND '1'='2",
  "1 OR 1=1",
  "admin'--",
  "1' ORDER BY 1--",
  "1' ORDER BY 10--",
];

const SQLI_TIME_BASED = [
  "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
  "1'; WAITFOR DELAY '0:0:3'--",
  "1' AND pg_sleep(3)--",
];

const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql_fetch/i,
  /ORA-\d{5}/i,
  /sqlite_/i,
  /unclosed quotation mark/i,
  /pg_query/i,
  /syntax error.*sql/i,
  /mysql_num_rows/i,
  /mysqli?/i,
  /PostgreSQL.*ERROR/i,
  /SQLite.*error/i,
  /ODBC.*error/i,
];

const SQLI_PATHS_LIGHT = ["/search", "/api/search", "/api/users", "/?q=", "/?id="];
const SQLI_PATHS_FULL = [
  "/search", "/api/search", "/api/users", "/api/items", "/api/products", "/api/orders",
  "/?q=", "/?id=", "/?user=", "/?search=", "/?filter=", "/?sort=",
  "/login", "/api/auth/login", "/api/trpc/", "/graphql",
];

async function testSQLInjection(scanId: number, targetUrl: string, scanMode: ScanMode): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing SQL injection vectors for ${targetUrl} (${scanMode} mode)`, "sqli");

  let payloads = scanMode === "full" ? [...SQLI_PAYLOADS_FULL] : SQLI_PAYLOADS_LIGHT;
  if (scanMode === "full") {
    const cache = await getPenTestCache();
    if (cache?.payloads?.sqli?.length) {
      const builtInSet = new Set(SQLI_PAYLOADS_FULL);
      const extra = cache.payloads.sqli.filter((p) => !builtInSet.has(p)).slice(0, 50);
      payloads = [...payloads, ...extra];
      await log(scanId, "debug", `Using ${extra.length} extra SQLi payloads from cache`, "sqli");
    }
  }
  const testPaths = scanMode === "full" ? SQLI_PATHS_FULL : SQLI_PATHS_LIGHT;
  const payloadLimit = scanMode === "full" ? payloads.length : 2;

  for (const path of testPaths) {
    for (const payload of payloads.slice(0, payloadLimit)) {
      try {
        const url = path.includes("?") ? `${path}${encodeURIComponent(payload)}` : path;
        const resp = await httpGet(targetUrl, url, {
          headers: { "X-Pentest-Scanner": "1" },
          timeout: 15000,
        });

        const isSqlError = SQL_ERROR_PATTERNS.some((p) => p.test(resp.body));
        if (isSqlError) {
          const reqPath = path.includes("?") ? `${path}${encodeURIComponent(payload)}` : path;
          findings.push({
            category: "SQL Injection",
            severity: "critical",
            title: `SQL injection vulnerability detected at ${path}`,
            description: "The application returned a SQL error message in response to an injection payload, indicating it may be vulnerable to SQL injection.",
            evidence: `Payload: ${payload}\nPath: ${path}\nResponse snippet: ${resp.body.substring(0, 300)}`,
            recommendation: "Use parameterised queries or prepared statements. Never interpolate user input into SQL strings. Implement input validation.",
            cweId: "CWE-89",
            owaspCategory: "A03:2021 – Injection",
            poc: {
              curlCommand: buildCurlCommand(targetUrl, reqPath, { headers: { "X-Pentest-Scanner": "1" } }),
              requestRaw: buildRawRequest(targetUrl, reqPath, { headers: { "X-Pentest-Scanner": "1" } }),
              responseSnippet: resp.body.substring(0, 500),
              reproductionSteps: [
                `1. Send a GET request to ${targetUrl}${reqPath}`,
                "2. Observe the SQL error message in the response body",
                "3. Confirm the application interpolates user input into SQL queries",
              ],
            },
          });
          await log(scanId, "error", `SQL injection evidence found at ${path}`, "sqli");
          break;
        }
      } catch {
        // continue
      }
    }
  }

  // Time-based blind SQLi (full mode only)
  if (scanMode === "full") {
    const timeBasedPaths = ["/?id=", "/api/users?id=", "/search?q="];
    for (const path of timeBasedPaths) {
      for (const payload of SQLI_TIME_BASED) {
        try {
          const start = Date.now();
          const url = `${path}${encodeURIComponent(payload)}`;
          await httpGet(targetUrl, url, { timeout: 8000 });
          const elapsed = Date.now() - start;
          if (elapsed >= 2800) {
            const tbPath = `${path}${encodeURIComponent(payload)}`;
            findings.push({
              category: "SQL Injection",
              severity: "critical",
              title: `Time-based blind SQL injection at ${path}`,
              description: `Response delayed by ~${Math.round(elapsed / 1000)}s, indicating possible time-based SQL injection.`,
              evidence: `Payload: ${payload}\nPath: ${path}\nDelay: ${elapsed}ms`,
              recommendation: "Use parameterised queries. Time-based injection suggests blind SQLi is exploitable.",
              cweId: "CWE-89",
              owaspCategory: "A03:2021 – Injection",
              poc: {
                curlCommand: buildCurlCommand(targetUrl, tbPath),
                requestRaw: buildRawRequest(targetUrl, tbPath),
                responseSnippet: `Response delayed by ${elapsed}ms (expected ~3000ms for SLEEP payload)`,
                reproductionSteps: [
                  `1. Send: ${buildCurlCommand(targetUrl, tbPath)}`,
                  `2. Measure response time — expected ~3 second delay`,
                  "3. A delay confirms the SQL SLEEP/WAITFOR payload executed server-side",
                ],
              },
            });
            await log(scanId, "error", `Time-based SQLi detected at ${path}`, "sqli");
            break;
          }
        } catch {
          // timeout or error — could indicate vulnerability
        }
      }
    }
  }

  if (findings.length === 0) {
    await log(scanId, "success", "No SQL injection vulnerabilities detected in tested endpoints", "sqli");
  }

  await log(scanId, "success", `SQL injection scan complete. Found ${findings.length} issue(s).`, "sqli");
  return findings;
}

// ─── XSS Test ─────────────────────────────────────────────────────────────────
const XSS_PAYLOADS_LIGHT = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
];

const XSS_PAYLOADS_FULL = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "javascript:alert(1)",
  "<svg onload=alert(1)>",
  "<body onload=alert(1)>",
  "<input onfocus=alert(1) autofocus>",
  "<marquee onstart=alert(1)>",
  "<details open ontoggle=alert(1)>",
  "'-alert(1)-'",
  "\"><script>alert(1)</script>",
  "<iframe src=\"javascript:alert(1)\">",
  "<svg/onload=alert(1)>",
  "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
];

const XSS_PATHS_LIGHT = ["/search?q=", "/api/search?q=", "/?q=", "/comment?text="];
const XSS_PATHS_FULL = [
  "/search?q=", "/api/search?q=", "/?q=", "/comment?text=", "/?search=", "/?query=",
  "/?name=", "/?message=", "/?content=", "/?redirect=", "/?url=", "/?return=",
  "/api/users?filter=", "/api/items?sort=",
];

async function testXSS(scanId: number, targetUrl: string, scanMode: ScanMode): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing XSS vulnerabilities for ${targetUrl} (${scanMode} mode)`, "xss");

  let payloads = scanMode === "full" ? [...XSS_PAYLOADS_FULL] : XSS_PAYLOADS_LIGHT;
  if (scanMode === "full") {
    const cache = await getPenTestCache();
    if (cache?.payloads?.xss?.length) {
      const builtInSet = new Set(XSS_PAYLOADS_FULL);
      const extra = cache.payloads.xss.filter((p) => !builtInSet.has(p)).slice(0, 30);
      payloads = [...payloads, ...extra];
      await log(scanId, "debug", `Using ${extra.length} extra XSS payloads from cache`, "xss");
    }
  }
  const testPaths = scanMode === "full" ? XSS_PATHS_FULL : XSS_PATHS_LIGHT;
  const payloadLimit = scanMode === "full" ? payloads.length : 2;

  for (const path of testPaths) {
    for (const payload of payloads.slice(0, payloadLimit)) {
      try {
        const resp = await httpGet(targetUrl, `${path}${encodeURIComponent(payload)}`);
        if (resp.body.includes(payload) && !resp.body.includes(`&lt;script&gt;`)) {
          const xssPath = `${path}${encodeURIComponent(payload)}`;
          findings.push({
            category: "Cross-Site Scripting",
            severity: "high",
            title: `Reflected XSS vulnerability at ${path}`,
            description: "User-supplied input is reflected in the response without proper encoding, enabling cross-site scripting attacks.",
            evidence: `Payload: ${payload}\nPath: ${path}`,
            recommendation: "Encode all user-supplied data before rendering in HTML. Implement a strict Content-Security-Policy.",
            cweId: "CWE-79",
            owaspCategory: "A03:2021 – Injection",
            poc: {
              curlCommand: buildCurlCommand(targetUrl, xssPath),
              requestRaw: buildRawRequest(targetUrl, xssPath),
              responseSnippet: resp.body.substring(0, 500),
              reproductionSteps: [
                `1. Open ${targetUrl}${xssPath} in a browser`,
                "2. Observe the XSS payload is rendered unescaped in the page",
                "3. Confirm user input is reflected without encoding",
              ],
            },
          });
          await log(scanId, "error", `Reflected XSS found at ${path}`, "xss");
          break;
        }
      } catch {
        // continue
      }
    }
  }

  if (findings.length === 0) {
    await log(scanId, "success", "No reflected XSS vulnerabilities detected in tested endpoints", "xss");
  }

  await log(scanId, "success", `XSS scan complete. Found ${findings.length} issue(s).`, "xss");
  return findings;
}

// ─── SPA Fallback Detection (reduces false positives) ───────────────────────────
/** Returns true if response looks like SPA fallback (index.html), not actual file content. Exported for tests. */
export function isSpaFallback(body: string, contentType: string): boolean {
  const ct = (contentType || "").toLowerCase();
  if (ct.includes("text/html")) {
    const trimmed = body.trim().toLowerCase();
    return trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html");
  }
  return false;
}

/** Check if body contains file-specific content (real exposure vs SPA fallback). Exported for tests. */
export function hasFileSpecificContent(path: string, body: string): boolean {
  const b = body.substring(0, 2000);
  if (path.includes(".env")) {
    return /^[A-Z_][A-Z0-9_]*\s*=/m.test(b) && !b.trim().toLowerCase().startsWith("<!doctype");
  }
  if (path.includes(".git/config")) {
    return /\[core\]|\[remote\]/.test(b) && !b.trim().toLowerCase().startsWith("<!doctype");
  }
  if (path.includes("phpinfo")) {
    return /PHP Version|Configuration|phpinfo\(\)/i.test(b);
  }
  if (path.includes("wp-admin")) {
    return /wordpress|wp-login|wp-admin/i.test(b);
  }
  return false;
}

// ─── Intelligence Gathering ───────────────────────────────────────────────────
const SENSITIVE_PATHS_LIGHT = [
  { path: "/.env", name: "Environment file", critical: true },
  { path: "/.git/config", name: "Git configuration", critical: true },
  { path: "/phpinfo.php", name: "PHP info page", critical: true },
  { path: "/admin", name: "Admin panel", critical: false },
  { path: "/wp-admin", name: "WordPress admin", critical: false },
  { path: "/api/docs", name: "API documentation", critical: false },
  { path: "/swagger.json", name: "Swagger/OpenAPI spec", critical: false },
  { path: "/robots.txt", name: "Robots.txt", critical: false, informational: true },
  { path: "/sitemap.xml", name: "Sitemap", critical: false, informational: true },
  { path: "/.well-known/security.txt", name: "Security.txt", critical: false, informational: true },
];

const SENSITIVE_PATHS_FULL = [
  ...SENSITIVE_PATHS_LIGHT,
  { path: "/.env.backup", name: "Environment backup", critical: true },
  { path: "/.env.local", name: "Local env file", critical: true },
  { path: "/.env.production", name: "Production env", critical: true },
  { path: "/.git/HEAD", name: "Git HEAD", critical: true },
  { path: "/config.php", name: "PHP config", critical: true },
  { path: "/config.json", name: "Config JSON", critical: false },
  { path: "/web.config", name: "IIS config", critical: false },
  { path: "/.htaccess", name: "Apache config", critical: false },
  { path: "/backup.sql", name: "Database backup", critical: true },
  { path: "/dump.sql", name: "SQL dump", critical: true },
  { path: "/database.sql", name: "Database file", critical: true },
  { path: "/.DS_Store", name: "macOS metadata", critical: false },
  { path: "/package.json", name: "Package manifest", critical: false },
  { path: "/composer.json", name: "Composer manifest", critical: false },
  { path: "/.dockerignore", name: "Docker ignore", critical: false },
  { path: "/docker-compose.yml", name: "Docker Compose", critical: false },
  { path: "/.npmrc", name: "NPM config", critical: false },
  { path: "/.yarnrc", name: "Yarn config", critical: false },
  { path: "/api/swagger.json", name: "Swagger API", critical: false },
  { path: "/openapi.json", name: "OpenAPI spec", critical: false },
  { path: "/graphql", name: "GraphQL endpoint", critical: false },
  { path: "/.well-known/acme-challenge/", name: "ACME challenge", critical: false },
];

async function testIntelligenceGathering(scanId: number, targetUrl: string, scanMode: ScanMode): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Running intelligence gathering for ${targetUrl} (${scanMode} mode)`, "recon");

  const sensitivePaths = scanMode === "full" ? SENSITIVE_PATHS_FULL : SENSITIVE_PATHS_LIGHT;

  for (const { path, name, critical, informational } of sensitivePaths) {
    try {
      const { status, body, headers } = await httpGet(targetUrl, path);
      const contentType = headers["content-type"] || "";

      if (status !== 200) continue;

      // Skip informational paths — not vulnerabilities (robots.txt, sitemap, security.txt)
      if (informational) {
        await log(scanId, "info", `Found ${name} at ${path} (informational, not flagged)`, "recon");
        continue;
      }

      // SPA fallback check: if response is HTML shell, likely not real file exposure
      if (isSpaFallback(body, contentType)) {
        // Only report if we see file-specific content (real leak)
        if (hasFileSpecificContent(path, body)) {
          findings.push({
            category: "Information Disclosure",
            severity: critical ? "critical" : "high",
            title: `${name} accessible at ${path}`,
            description: `Sensitive file ${path} appears to be publicly accessible. Response contains file-specific content.`,
            evidence: `HTTP ${status}: ${body.substring(0, 200)}`,
            recommendation: `Restrict access to ${path}. Remove sensitive files from web root.`,
            cweId: "CWE-538",
            owaspCategory: "A05:2021 – Security Misconfiguration",
          });
          await log(scanId, "error", `CRITICAL: ${name} exposed at ${path}`, "recon");
        } else {
          await log(scanId, "info", `SPA fallback at ${path} (HTML shell, not real file — suppressed)`, "recon");
        }
        continue;
      }

      // Non-HTML 200: could be real file exposure
      if (critical && (path.includes(".env") || path.includes(".git") || path.includes("phpinfo"))) {
        findings.push({
          category: "Information Disclosure",
          severity: "critical",
          title: `${name} accessible at ${path}`,
          description: `Sensitive file ${path} is publicly accessible (non-HTML response).`,
          evidence: `HTTP ${status}, Content-Type: ${contentType}\n${body.substring(0, 200)}`,
          recommendation: `Immediately restrict access to ${path}. Remove from web root.`,
          cweId: "CWE-538",
          owaspCategory: "A05:2021 – Security Misconfiguration",
        });
        await log(scanId, "error", `CRITICAL: ${name} exposed at ${path}`, "recon");
      } else if (!critical) {
        findings.push({
          category: "Information Disclosure",
          severity: "info",
          title: `${name} accessible at ${path}`,
          description: `${name} found at ${path}. Review whether it should be publicly accessible.`,
          evidence: `HTTP ${status}`,
          recommendation: `Review exposure of ${path}.`,
        });
        await log(scanId, "info", `Found: ${name} at ${path} (HTTP ${status})`, "recon");
      }
    } catch {
      // continue
    }
  }

  await log(scanId, "success", `Intelligence gathering complete. Found ${findings.length} item(s).`, "recon");
  return findings;
}

// ─── CORS Misconfiguration (full mode) ───────────────────────────────────────
async function testCORS(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing CORS configuration for ${targetUrl}`, "cors");

  try {
    const resp = await httpGet(targetUrl, "/", {
      headers: {
        "Origin": "https://evil-attacker.com",
        "X-Requested-With": "XMLHttpRequest",
      },
    });

    const acao = resp.headers["access-control-allow-origin"];
    const acac = resp.headers["access-control-allow-credentials"];

    if (acao === "*" && acac === "true") {
      findings.push({
        category: "CORS",
        severity: "high",
        title: "CORS allows credentials with wildcard origin",
        description: "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is insecure. Any site can make credentialed requests.",
        evidence: `ACAO: ${acao}, ACAC: ${acac}`,
        recommendation: "Use a whitelist of allowed origins. Never combine wildcard with credentials.",
        cweId: "CWE-942",
        owaspCategory: "A05:2021 – Security Misconfiguration",
      });
    } else if (acao === "https://evil-attacker.com") {
      findings.push({
        category: "CORS",
        severity: "critical",
        title: "CORS reflects arbitrary Origin",
        description: "The server reflects the Origin header in Access-Control-Allow-Origin, allowing any site to make cross-origin requests.",
        evidence: `ACAO: ${acao}`,
        recommendation: "Validate Origin against a whitelist. Reject unknown origins.",
        cweId: "CWE-942",
        owaspCategory: "A05:2021 – Security Misconfiguration",
      });
    } else if (acao && acao !== "*") {
      await log(scanId, "info", `CORS configured with origin: ${acao}`, "cors");
    }
  } catch (err: any) {
    await log(scanId, "info", `CORS test skipped: ${err.message}`, "cors");
  }

  await log(scanId, "success", `CORS scan complete. Found ${findings.length} issue(s).`, "cors");
  return findings;
}

// ─── Directory Traversal (full mode) ──────────────────────────────────────────
async function testDirectoryTraversal(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing directory traversal for ${targetUrl}`, "traversal");

  const payloads = [
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//windows/win.ini",
  ];

  const testPaths = ["/api/file?path=", "/api/download?file=", "/?file=", "/?path=", "/api/read?path=", "/download?file="];
  const traversalIndicators = [/root:/, /\[boot\]/, /\[fonts\]/, /\[extensions\]/];

  for (const path of testPaths) {
    for (const payload of payloads) {
      try {
        const resp = await httpGet(targetUrl, `${path}${encodeURIComponent(payload)}`);
        if (resp.status === 200 && traversalIndicators.some((p) => p.test(resp.body))) {
          findings.push({
            category: "Path Traversal",
            severity: "critical",
            title: `Directory traversal at ${path}`,
            description: "The application returned sensitive system file content, indicating path traversal vulnerability.",
            evidence: `Path: ${path}\nPayload: ${payload}\nResponse snippet: ${resp.body.substring(0, 200)}`,
            recommendation: "Validate and sanitize file paths. Use allowlists. Never allow .. in paths.",
            cweId: "CWE-22",
            owaspCategory: "A01:2021 – Broken Access Control",
          });
          await log(scanId, "error", `Path traversal detected at ${path}`, "traversal");
          break;
        }
      } catch {
        // continue
      }
    }
  }

  await log(scanId, "success", `Directory traversal scan complete. Found ${findings.length} issue(s).`, "traversal");
  return findings;
}

// ─── HTTP Methods (full mode) ─────────────────────────────────────────────────
const CONFIG_REQUEST_TIMEOUT_MS = 8000;

async function testHTTPMethods(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing HTTP methods for ${targetUrl}`, "config");

  const methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT"];

  for (const method of methods) {
    try {
      // Hard timeout so CONNECT/TRACE etc. can never hang the scan (belt-and-suspenders with httpGet's own timeout)
      const result = await Promise.race([
        httpGet(targetUrl, "/", { method, timeout: CONFIG_REQUEST_TIMEOUT_MS }),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("Config request timeout")), CONFIG_REQUEST_TIMEOUT_MS)
        ),
      ]);
      const { status, headers, body } = result;
      if (method === "TRACE" && status === 200 && body.includes("TRACE") && body.includes("HTTP")) {
        findings.push({
          category: "Security Misconfiguration",
          severity: "medium",
          title: "HTTP TRACE method enabled",
          description: "TRACE allows cross-site tracing (XST) attacks. Attackers can steal credentials via cookies.",
          evidence: `TRACE returned 200 with reflected request`,
          recommendation: "Disable TRACE method on the web server.",
          cweId: "CWE-693",
          owaspCategory: "A05:2021 – Security Misconfiguration",
        });
      }
      if (method === "OPTIONS" && status === 200) {
        const allow = headers["allow"];
        if (allow && /PUT|DELETE|TRACE/i.test(allow)) {
          await log(scanId, "info", `Allowed methods: ${allow}`, "config");
        }
      }
    } catch {
      // continue
    }
  }

  await log(scanId, "success", `HTTP methods scan complete. Found ${findings.length} issue(s).`, "config");
  return findings;
}

// ─── PoC Helper ───────────────────────────────────────────────────────────────
/** Build a curl command equivalent for a given request. */
function buildCurlCommand(
  targetUrl: string,
  path: string,
  options: { method?: string; body?: string; headers?: Record<string, string> } = {}
): string {
  const fullUrl = path.startsWith("http") ? path : targetUrl + path;
  const parts = [`curl`];
  const method = options.method || "GET";
  if (method !== "GET") parts.push(`-X ${method}`);
  parts.push(`'${fullUrl}'`);
  if (options.headers) {
    for (const [k, v] of Object.entries(options.headers)) {
      if (k.toLowerCase() !== "user-agent") parts.push(`-H '${k}: ${v}'`);
    }
  }
  if (options.body) parts.push(`-d '${options.body.substring(0, 500)}'`);
  return parts.join(" ");
}

/** Build a raw HTTP request string. */
function buildRawRequest(
  targetUrl: string,
  path: string,
  options: { method?: string; body?: string; headers?: Record<string, string> } = {}
): string {
  const parsed = new URL(path.startsWith("http") ? path : targetUrl + path);
  const method = options.method || "GET";
  const lines = [`${method} ${parsed.pathname}${parsed.search} HTTP/1.1`, `Host: ${parsed.hostname}`];
  lines.push("User-Agent: PenTestPortal/1.0 Security Scanner");
  if (options.headers) {
    for (const [k, v] of Object.entries(options.headers)) lines.push(`${k}: ${v}`);
  }
  lines.push("");
  if (options.body) lines.push(options.body.substring(0, 500));
  return lines.join("\r\n");
}

// ─── Business Logic Tests (full mode) ─────────────────────────────────────────
async function testBusinessLogic(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing business logic for ${targetUrl}`, "logic");

  // Debug mode detection — check for debug endpoints and verbose headers
  const debugPaths = ["/debug", "/__debug__", "/actuator", "/actuator/health", "/metrics", "/_profiler", "/elmah.axd", "/trace", "/server-info"];
  for (const path of debugPaths) {
    try {
      const resp = await httpGet(targetUrl, path, { timeout: 5000 });
      if (resp.status >= 200 && resp.status < 400 && resp.body.length > 50) {
        findings.push({
          category: "Business Logic",
          severity: "medium",
          title: `Debug/diagnostic endpoint accessible: ${path}`,
          description: `The endpoint ${path} returned a successful response, potentially exposing internal application state, metrics, or debug information.`,
          evidence: `Path: ${path}\nStatus: ${resp.status}\nResponse length: ${resp.body.length}\nSnippet: ${resp.body.substring(0, 200)}`,
          recommendation: "Disable or restrict access to debug and diagnostic endpoints in production. Use authentication and IP whitelisting.",
          cweId: "CWE-215",
          owaspCategory: "A05:2021 – Security Misconfiguration",
          poc: {
            curlCommand: buildCurlCommand(targetUrl, path),
            requestRaw: buildRawRequest(targetUrl, path),
            responseSnippet: resp.body.substring(0, 500),
            reproductionSteps: [
              `1. Navigate to ${targetUrl}${path}`,
              "2. Observe the debug/diagnostic information in the response",
            ],
          },
        });
        await log(scanId, "warn", `Debug endpoint found: ${path} (${resp.status})`, "logic");
      }
    } catch { /* continue */ }
  }

  // Verbose error headers detection
  try {
    const resp = await httpGet(targetUrl, "/");
    const debugHeaders = ["x-debug", "x-debug-token", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"];
    for (const hdr of debugHeaders) {
      if (resp.headers[hdr]) {
        findings.push({
          category: "Business Logic",
          severity: "low",
          title: `Debug/verbose header present: ${hdr}`,
          description: `The response includes the header ${hdr}: ${resp.headers[hdr]}, which may reveal internal implementation details.`,
          evidence: `Header: ${hdr}: ${resp.headers[hdr]}`,
          recommendation: `Remove or suppress the ${hdr} header in production to reduce information disclosure.`,
          cweId: "CWE-200",
          owaspCategory: "A05:2021 – Security Misconfiguration",
        });
      }
    }
  } catch { /* continue */ }

  // CSRF token validation — attempt a state-changing request without a CSRF token
  try {
    const loginResp = await httpGet(targetUrl, "/login", { timeout: 5000 });
    const csrfPatterns = [
      /name=["']?csrf/i, /name=["']?_csrf/i, /name=["']?csrfmiddlewaretoken/i,
      /name=["']?_token/i, /name=["']?authenticity_token/i, /csrf-token/i,
    ];
    const hasCSRFField = csrfPatterns.some((p) => p.test(loginResp.body));
    if (loginResp.status >= 200 && loginResp.status < 400 && !hasCSRFField && loginResp.body.includes("<form")) {
      findings.push({
        category: "Business Logic",
        severity: "medium",
        title: "No CSRF token detected in login form",
        description: "The login form does not appear to include a CSRF protection token. This may allow cross-site request forgery attacks.",
        evidence: `Path: /login\nForm detected: yes\nCSRF token field: not found`,
        recommendation: "Implement CSRF protection on all state-changing forms. Use a framework-provided CSRF middleware.",
        cweId: "CWE-352",
        owaspCategory: "A01:2021 – Broken Access Control",
      });
    }
  } catch { /* continue */ }

  // Mass assignment detection — send unexpected fields in POST body
  const massAssignPaths = ["/api/users", "/api/user", "/api/account", "/api/profile", "/api/register"];
  for (const path of massAssignPaths) {
    try {
      const payload = JSON.stringify({ name: "test", email: "test@test.com", role: "admin", isAdmin: true });
      const resp = await httpGet(targetUrl, path, {
        method: "POST",
        body: payload,
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      });
      if (resp.status >= 200 && resp.status < 300) {
        const bodyLower = resp.body.toLowerCase();
        if (bodyLower.includes('"role"') && bodyLower.includes('"admin"') || bodyLower.includes('"isadmin"') && bodyLower.includes("true")) {
          findings.push({
            category: "Business Logic",
            severity: "high",
            title: `Potential mass assignment at ${path}`,
            description: `The endpoint accepted and reflected unexpected fields (role, isAdmin) in the response, suggesting mass assignment vulnerability.`,
            evidence: `Path: ${path}\nPayload included: role=admin, isAdmin=true\nResponse: ${resp.body.substring(0, 300)}`,
            recommendation: "Use allowlists for accepted fields in API endpoints. Never blindly bind request parameters to database models.",
            cweId: "CWE-915",
            owaspCategory: "A01:2021 – Broken Access Control",
            poc: {
              curlCommand: buildCurlCommand(targetUrl, path, { method: "POST", body: payload, headers: { "Content-Type": "application/json" } }),
              requestRaw: buildRawRequest(targetUrl, path, { method: "POST", body: payload, headers: { "Content-Type": "application/json" } }),
              responseSnippet: resp.body.substring(0, 500),
              reproductionSteps: [
                `1. Send a POST to ${targetUrl}${path} with body: ${payload}`,
                "2. Observe that role/isAdmin fields are reflected in the response",
                "3. Confirm that the server accepted the escalated privilege fields",
              ],
            },
          });
        }
      }
    } catch { /* continue */ }
  }

  // Stack trace / verbose error detection
  try {
    const errorPaths = ["/api/nonexistent-endpoint-test-404", "/throw", "/error"];
    for (const path of errorPaths) {
      try {
        const resp = await httpGet(targetUrl, path, { timeout: 5000 });
        const tracePatterns = [/at\s+\S+\s+\(/i, /Traceback \(most recent call last\)/i, /Exception in thread/i, /stack trace:/i, /node_modules\//i];
        if (tracePatterns.some((p) => p.test(resp.body))) {
          findings.push({
            category: "Business Logic",
            severity: "medium",
            title: `Stack trace/verbose error exposed at ${path}`,
            description: "The application returns detailed stack traces or internal error information, revealing implementation details.",
            evidence: `Path: ${path}\nSnippet: ${resp.body.substring(0, 300)}`,
            recommendation: "Configure custom error pages for production. Never expose stack traces or internal errors to end users.",
            cweId: "CWE-209",
            owaspCategory: "A05:2021 – Security Misconfiguration",
          });
          break;
        }
      } catch { /* continue */ }
    }
  } catch { /* continue */ }

  await log(scanId, "success", `Business logic scan complete. Found ${findings.length} issue(s).`, "logic");
  return findings;
}

// ─── SSRF Probe ──────────────────────────────────────────────────────────────

const SSRF_PARAMS = ["url", "redirect", "callback", "next", "target", "return", "dest", "uri", "path", "go", "return_to", "redirect_uri"];

const SSRF_PAYLOADS = [
  { payload: "http://127.0.0.1", name: "localhost IPv4" },
  { payload: "http://[::1]", name: "localhost IPv6" },
  { payload: "http://169.254.169.254/latest/meta-data/", name: "AWS metadata" },
  { payload: "http://metadata.google.internal/", name: "GCP metadata" },
  { payload: "http://0x7f000001", name: "hex localhost" },
  { payload: "http://2130706433", name: "decimal localhost" },
];

/** Test for Server-Side Request Forgery (SSRF) vulnerabilities */
export async function testSSRF(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing for SSRF vulnerabilities on ${targetUrl}`, "ssrf");

  const baseResp = await httpGet(targetUrl, "/").catch(() => null);
  if (!baseResp) {
    await log(scanId, "warn", "Target not reachable for SSRF testing", "ssrf");
    return findings;
  }

  for (const param of SSRF_PARAMS) {
    for (const { payload, name } of SSRF_PAYLOADS) {
      try {
        const path = `/?${param}=${encodeURIComponent(payload)}`;
        const resp = await httpGet(targetUrl, path, { timeout: 5000 });

        const suspicious =
          resp.status === 200 && (
            resp.body.includes("ami-") ||
            resp.body.includes("instance-id") ||
            resp.body.includes("computeMetadata") ||
            resp.body.includes("127.0.0.1") ||
            resp.body.includes("localhost") ||
            (resp.body.length > 0 && resp.body !== baseResp.body && resp.body.length !== baseResp.body.length)
          );

        if (suspicious) {
          const title = `Potential SSRF via ${param} parameter (${name})`;
          findings.push({
            category: "SSRF",
            severity: "high",
            title,
            description: `The parameter '${param}' accepted an internal URL (${name}) and returned a different response, suggesting the server may be fetching the provided URL.`,
            evidence: `GET ${path} → ${resp.status} (${resp.body.length} bytes)\nResponse snippet: ${resp.body.substring(0, 300)}`,
            recommendation: "Validate and sanitize URL parameters server-side. Block requests to internal/private IP ranges. Use an allowlist for permitted external domains.",
            cweId: "CWE-918",
            owaspCategory: "A10:2021 – Server-Side Request Forgery",
            poc: {
              curlCommand: `curl "${targetUrl}${path}"`,
              requestRaw: `GET ${path} HTTP/1.1\nHost: ${new URL(targetUrl).host}`,
              responseSnippet: `HTTP ${resp.status}\n${resp.body.substring(0, 300)}`,
              reproductionSteps: [
                `Navigate to ${targetUrl}${path}`,
                `Observe the response differs from the base page and may contain internal service data`,
                `Try varying the ${param} parameter with other internal IPs or cloud metadata URLs`,
              ],
            },
          });
          await log(scanId, "warn", `VULN: ${title}`, "ssrf");
          break;
        }
      } catch {
        // timeout or error — expected for blocked requests
      }
    }
  }

  if (findings.length === 0) {
    await log(scanId, "success", "SSRF checks: PASS — no SSRF indicators detected", "ssrf");
  }

  return findings;
}

// ─── GraphQL Scanning ─────────────────────────────────────────────────────────
async function testGraphQL(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing GraphQL endpoints for ${targetUrl}`, "graphql");

  const graphqlPaths = ["/graphql", "/api/graphql", "/__graphql", "/gql", "/query", "/v1/graphql"];
  let detectedPath: string | null = null;

  // Detect GraphQL endpoint
  for (const path of graphqlPaths) {
    try {
      const resp = await httpGet(targetUrl, path, {
        method: "POST",
        body: JSON.stringify({ query: "{ __typename }" }),
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      });
      if (resp.status >= 200 && resp.status < 400 && (resp.body.includes('"data"') || resp.body.includes('"errors"') || resp.body.includes("__typename"))) {
        detectedPath = path;
        await log(scanId, "info", `GraphQL endpoint detected at ${path}`, "graphql");
        break;
      }
    } catch { /* continue */ }
  }

  if (!detectedPath) {
    await log(scanId, "info", "No GraphQL endpoint detected — skipping GraphQL tests", "graphql");
    return findings;
  }

  // Introspection query test
  const introspectionQuery = '{"query":"{ __schema { types { name description } queryType { name } mutationType { name } } }"}';
  try {
    const resp = await httpGet(targetUrl, detectedPath, {
      method: "POST",
      body: introspectionQuery,
      headers: { "Content-Type": "application/json" },
      timeout: 10000,
    });
    if (resp.status >= 200 && resp.status < 400 && resp.body.includes("__schema") && resp.body.includes("types")) {
      let typeCount = 0;
      try { typeCount = (resp.body.match(/"name"/g) || []).length; } catch { /* ignore */ }
      findings.push({
        category: "GraphQL",
        severity: "medium",
        title: "GraphQL introspection is enabled",
        description: `The GraphQL endpoint at ${detectedPath} allows introspection queries, exposing the full API schema (${typeCount} types detected). This enables attackers to map the entire API surface.`,
        evidence: `Path: ${detectedPath}\nIntrospection: enabled\nTypes discovered: ~${typeCount}\nResponse snippet: ${resp.body.substring(0, 300)}`,
        recommendation: "Disable GraphQL introspection in production environments. Most GraphQL frameworks support disabling it via configuration.",
        cweId: "CWE-200",
        owaspCategory: "A05:2021 – Security Misconfiguration",
        poc: {
          curlCommand: buildCurlCommand(targetUrl, detectedPath, { method: "POST", body: introspectionQuery, headers: { "Content-Type": "application/json" } }),
          requestRaw: buildRawRequest(targetUrl, detectedPath, { method: "POST", body: introspectionQuery, headers: { "Content-Type": "application/json" } }),
          responseSnippet: resp.body.substring(0, 500),
          reproductionSteps: [
            `1. Send POST to ${targetUrl}${detectedPath} with body: ${introspectionQuery}`,
            "2. Observe the full schema is returned, including all types, queries, and mutations",
          ],
        },
      });
    }
  } catch { /* continue */ }

  // Batch query abuse — send multiple operations in one request
  try {
    const batchQuery = JSON.stringify([
      { query: "{ __typename }" },
      { query: "{ __typename }" },
      { query: "{ __typename }" },
      { query: "{ __typename }" },
      { query: "{ __typename }" },
    ]);
    const resp = await httpGet(targetUrl, detectedPath, {
      method: "POST",
      body: batchQuery,
      headers: { "Content-Type": "application/json" },
      timeout: 10000,
    });
    if (resp.status >= 200 && resp.status < 400) {
      let isBatch = false;
      try { const parsed = JSON.parse(resp.body); isBatch = Array.isArray(parsed) && parsed.length >= 5; } catch { /* ignore */ }
      if (isBatch) {
        findings.push({
          category: "GraphQL",
          severity: "medium",
          title: "GraphQL batch query abuse possible",
          description: `The GraphQL endpoint at ${detectedPath} accepts batched queries without limit. An attacker can send thousands of operations in a single request to perform denial-of-service or brute-force attacks.`,
          evidence: `Path: ${detectedPath}\nBatch of 5 queries accepted\nResponse: ${resp.body.substring(0, 200)}`,
          recommendation: "Limit the number of operations per GraphQL request. Implement query cost analysis and rate limiting.",
          cweId: "CWE-770",
          owaspCategory: "A04:2021 – Insecure Design",
        });
      }
    }
  } catch { /* continue */ }

  // SQL injection via GraphQL arguments
  const sqliPayloads = ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT null--"];
  for (const payload of sqliPayloads) {
    try {
      const query = JSON.stringify({ query: `{ user(id: "${payload}") { id } }` });
      const resp = await httpGet(targetUrl, detectedPath, {
        method: "POST",
        body: query,
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      });
      const sqlErrors = [/sql syntax/i, /mysql/i, /postgresql/i, /sqlite/i, /ORA-\d/i, /SQLSTATE/i, /unclosed quotation/i];
      if (sqlErrors.some((p) => p.test(resp.body))) {
        findings.push({
          category: "GraphQL",
          severity: "critical",
          title: `SQL injection via GraphQL at ${detectedPath}`,
          description: "SQL error patterns detected in GraphQL response when injection payloads are sent as arguments.",
          evidence: `Payload: ${payload}\nResponse: ${resp.body.substring(0, 300)}`,
          recommendation: "Use parameterised queries in GraphQL resolvers. Never interpolate user input into SQL strings.",
          cweId: "CWE-89",
          owaspCategory: "A03:2021 – Injection",
          poc: {
            curlCommand: buildCurlCommand(targetUrl, detectedPath, { method: "POST", body: query, headers: { "Content-Type": "application/json" } }),
            requestRaw: buildRawRequest(targetUrl, detectedPath, { method: "POST", body: query, headers: { "Content-Type": "application/json" } }),
            responseSnippet: resp.body.substring(0, 500),
            reproductionSteps: [
              `1. Send POST to ${targetUrl}${detectedPath} with body: ${query}`,
              "2. Observe SQL error in the response",
            ],
          },
        });
        break;
      }
    } catch { /* continue */ }
  }

  // Deeply nested query (resource exhaustion)
  try {
    const deepQuery = JSON.stringify({ query: "{ __typename ".repeat(20) + "}" .repeat(20) });
    const resp = await httpGet(targetUrl, detectedPath, {
      method: "POST",
      body: deepQuery,
      headers: { "Content-Type": "application/json" },
      timeout: 10000,
    });
    if (resp.status >= 200 && resp.status < 400 && !resp.body.includes("complexity") && !resp.body.includes("depth")) {
      findings.push({
        category: "GraphQL",
        severity: "low",
        title: "No query depth limiting detected",
        description: "The GraphQL endpoint does not appear to enforce query depth limits, which could allow denial-of-service via deeply nested queries.",
        evidence: `20-level deep query accepted (status ${resp.status})`,
        recommendation: "Implement query depth limiting and query cost analysis to prevent resource exhaustion attacks.",
        cweId: "CWE-400",
        owaspCategory: "A04:2021 – Insecure Design",
      });
    }
  } catch { /* continue */ }

  await log(scanId, "success", `GraphQL scan complete. Found ${findings.length} issue(s).`, "graphql");
  return findings;
}

// ─── SSL/TLS Deep Analysis (full mode) ───────────────────────────────────────
async function testSSLTLS(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing SSL/TLS configuration for ${targetUrl}`, "tls");

  const parsed = new URL(targetUrl);
  if (parsed.protocol !== "https:") {
    findings.push({
      category: "TLS",
      severity: "high",
      title: "Target does not use HTTPS",
      description: "The target URL uses plain HTTP. All traffic is transmitted in cleartext.",
      evidence: `Protocol: ${parsed.protocol}`,
      recommendation: "Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
      cweId: "CWE-319",
      owaspCategory: "A02:2021 – Cryptographic Failures",
    });
    await log(scanId, "warn", "Target uses HTTP — skipping TLS analysis", "tls");
    return findings;
  }

  // Native TLS checks via Node's tls module
  try {
    const tls = await import("tls");
    const hostname = parsed.hostname;
    const port = parsed.port ? Number(parsed.port) : 443;

    const certInfo = await new Promise<{
      protocol: string;
      cipher: string;
      cert: {
        subject: Record<string, string>;
        issuer: Record<string, string>;
        valid_from: string;
        valid_to: string;
        serialNumber: string;
        fingerprint256: string;
      };
    }>((resolve, reject) => {
      const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 10000 }, () => {
        const protocol = socket.getProtocol?.() ?? "unknown";
        const cipherInfo = socket.getCipher?.();
        const cert = socket.getPeerCertificate?.();
        socket.destroy();
        resolve({
          protocol,
          cipher: cipherInfo ? `${cipherInfo.name} (${cipherInfo.version})` : "unknown",
          cert: cert ? {
            subject: cert.subject as unknown as Record<string, string>,
            issuer: cert.issuer as unknown as Record<string, string>,
            valid_from: cert.valid_from,
            valid_to: cert.valid_to,
            serialNumber: cert.serialNumber,
            fingerprint256: cert.fingerprint256,
          } : { subject: {}, issuer: {}, valid_from: "", valid_to: "", serialNumber: "", fingerprint256: "" },
        });
      });
      socket.on("error", reject);
      socket.on("timeout", () => { socket.destroy(); reject(new Error("TLS timeout")); });
    });

    await log(scanId, "info", `TLS protocol: ${certInfo.protocol}, Cipher: ${certInfo.cipher}`, "tls");

    // Check TLS version
    const proto = certInfo.protocol.toLowerCase();
    if (proto.includes("tlsv1.0") || proto === "tlsv1") {
      findings.push({
        category: "TLS",
        severity: "high",
        title: "TLS 1.0 supported",
        description: "The server supports TLS 1.0, which has known vulnerabilities (POODLE, BEAST). TLS 1.0 is deprecated.",
        evidence: `Negotiated protocol: ${certInfo.protocol}`,
        recommendation: "Disable TLS 1.0 and 1.1. Require TLS 1.2 or 1.3 minimum.",
        cweId: "CWE-326",
        owaspCategory: "A02:2021 – Cryptographic Failures",
      });
    } else if (proto.includes("tlsv1.1")) {
      findings.push({
        category: "TLS",
        severity: "medium",
        title: "TLS 1.1 supported",
        description: "The server supports TLS 1.1, which is deprecated. Modern browsers have dropped TLS 1.1 support.",
        evidence: `Negotiated protocol: ${certInfo.protocol}`,
        recommendation: "Disable TLS 1.1. Require TLS 1.2 or 1.3 minimum.",
        cweId: "CWE-326",
        owaspCategory: "A02:2021 – Cryptographic Failures",
      });
    } else {
      await log(scanId, "success", `TLS version: ${certInfo.protocol} (acceptable)`, "tls");
    }

    // Check for weak ciphers
    const weakCiphers = /RC4|DES|3DES|EXPORT|NULL|MD5|anon/i;
    if (weakCiphers.test(certInfo.cipher)) {
      findings.push({
        category: "TLS",
        severity: "high",
        title: `Weak cipher suite: ${certInfo.cipher}`,
        description: "The server is using a weak or deprecated cipher suite that may be vulnerable to cryptographic attacks.",
        evidence: `Cipher: ${certInfo.cipher}`,
        recommendation: "Configure the server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305). Disable RC4, DES, 3DES, and export ciphers.",
        cweId: "CWE-326",
        owaspCategory: "A02:2021 – Cryptographic Failures",
      });
    }

    // Check certificate expiry
    if (certInfo.cert.valid_to) {
      const expiryDate = new Date(certInfo.cert.valid_to);
      const now = new Date();
      const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      if (daysUntilExpiry < 0) {
        findings.push({
          category: "TLS",
          severity: "critical",
          title: "SSL certificate has expired",
          description: `The server certificate expired on ${certInfo.cert.valid_to}. Browsers will show security warnings.`,
          evidence: `Expires: ${certInfo.cert.valid_to} (${Math.abs(daysUntilExpiry)} days ago)\nSubject: ${JSON.stringify(certInfo.cert.subject)}\nIssuer: ${JSON.stringify(certInfo.cert.issuer)}`,
          recommendation: "Renew the SSL certificate immediately.",
          cweId: "CWE-295",
          owaspCategory: "A02:2021 – Cryptographic Failures",
        });
      } else if (daysUntilExpiry < 30) {
        findings.push({
          category: "TLS",
          severity: "medium",
          title: `SSL certificate expires in ${daysUntilExpiry} days`,
          description: `The server certificate expires on ${certInfo.cert.valid_to}. Renew before expiry to avoid service disruption.`,
          evidence: `Expires: ${certInfo.cert.valid_to}\nSubject: ${JSON.stringify(certInfo.cert.subject)}`,
          recommendation: "Renew the SSL certificate before expiry. Consider automated renewal (e.g. Let's Encrypt with certbot).",
          cweId: "CWE-295",
          owaspCategory: "A02:2021 – Cryptographic Failures",
        });
      } else {
        await log(scanId, "success", `Certificate valid for ${daysUntilExpiry} days (expires ${certInfo.cert.valid_to})`, "tls");
      }
    }

    // Check for self-signed certificate
    if (certInfo.cert.subject && certInfo.cert.issuer) {
      const subjCN = certInfo.cert.subject.CN || "";
      const issuerCN = certInfo.cert.issuer.CN || "";
      const issuerO = certInfo.cert.issuer.O || "";
      if (subjCN === issuerCN && !issuerO) {
        findings.push({
          category: "TLS",
          severity: "medium",
          title: "Self-signed SSL certificate detected",
          description: "The server uses a self-signed certificate, which is not trusted by browsers and may indicate a misconfiguration.",
          evidence: `Subject CN: ${subjCN}\nIssuer CN: ${issuerCN}`,
          recommendation: "Use a certificate from a trusted Certificate Authority (e.g. Let's Encrypt).",
          cweId: "CWE-295",
          owaspCategory: "A02:2021 – Cryptographic Failures",
        });
      }
    }
  } catch (err: any) {
    await log(scanId, "warn", `Native TLS check error: ${err.message}`, "tls");
  }

  // Try testssl.sh if installed
  try {
    const { execSync } = await import("child_process");
    const { existsSync } = await import("fs");
    const testsslPaths = ["/usr/local/bin/testssl.sh", "/usr/bin/testssl.sh", "/opt/testssl/testssl.sh", "testssl.sh"];
    const testsslCmd = testsslPaths.find((p) => {
      if (p === "testssl.sh") {
        try { execSync("which testssl.sh", { stdio: "ignore" }); return true; } catch { return false; }
      }
      return existsSync(p);
    });

    if (testsslCmd) {
      await log(scanId, "info", "testssl.sh found — running deep TLS analysis (up to 3 minutes)...", "tls");
      const host = parsed.hostname + (parsed.port ? `:${parsed.port}` : "");
      const { stdout } = await execCapture(
        `${testsslCmd} --quiet --color 0 --severity LOW --sneaky ${host} 2>&1`,
        { timeout: 180000, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }
      );
      if (stdout) {
        await log(scanId, "info", stdout.substring(0, 2000), "tls");
        const lines = stdout.split("\n");
        for (const line of lines) {
          const vulnMatch = line.match(/VULNERABLE|NOT ok|WARN/i);
          if (vulnMatch && !line.includes("not vulnerable") && !line.includes("NOT VULNERABLE")) {
            const sev: Finding["severity"] = /CRITICAL|HIGH/i.test(line) ? "high" : "medium";
            findings.push({
              category: "TLS",
              severity: sev,
              title: `testssl: ${line.trim().substring(0, 150)}`,
              description: line.trim(),
              recommendation: "Review and remediate the TLS configuration issue identified by testssl.sh.",
              cweId: "CWE-326",
              owaspCategory: "A02:2021 – Cryptographic Failures",
            });
          }
        }
        await log(scanId, "info", `testssl.sh found ${findings.length} TLS finding(s)`, "tls");
      }
    } else {
      await log(scanId, "info", "testssl.sh not installed (optional). Native TLS checks completed.", "tls");
    }
  } catch (err: any) {
    await log(scanId, "warn", `testssl.sh check failed: ${err.message}`, "tls");
  }

  await log(scanId, "success", `TLS scan complete. Found ${findings.length} issue(s).`, "tls");
  return findings;
}

// ─── Attack Scenario Chain Analysis ───────────────────────────────────────────
export interface AttackScenario {
  id: string;
  title: string;
  objective: string;
  steps: { findingTitle: string; role: string }[];
  likelihood: "High" | "Medium" | "Low";
  impact: "High" | "Medium" | "Low";
}

interface ScenarioTemplate {
  id: string;
  title: string;
  objective: string;
  requiredCategories: string[][];
  likelihood: "High" | "Medium" | "Low";
  impact: "High" | "Medium" | "Low";
  stepRoles: string[];
}

const SCENARIO_TEMPLATES: ScenarioTemplate[] = [
  {
    id: "S-001",
    title: "Account Takeover via Brute Force",
    objective: "Gain unauthorised access to user accounts",
    requiredCategories: [["Authentication"], ["Authentication"]],
    likelihood: "High",
    impact: "High",
    stepRoles: ["Account enumeration reveals valid usernames", "Brute force attack succeeds due to no rate limiting"],
  },
  {
    id: "S-002",
    title: "Session Hijack via XSS and CORS",
    objective: "Steal authenticated user sessions",
    requiredCategories: [["Cross-Site Scripting"], ["CORS"]],
    likelihood: "Medium",
    impact: "High",
    stepRoles: ["XSS injects malicious script into victim's browser", "CORS misconfiguration allows cross-origin credential theft"],
  },
  {
    id: "S-003",
    title: "Data Exfiltration via SQL Injection",
    objective: "Extract sensitive data from the application database",
    requiredCategories: [["SQL Injection"]],
    likelihood: "High",
    impact: "High",
    stepRoles: ["SQL injection allows direct database query execution and data extraction"],
  },
  {
    id: "S-004",
    title: "Unauthorised File Access via Traversal",
    objective: "Read sensitive server files (credentials, configuration)",
    requiredCategories: [["Path Traversal"]],
    likelihood: "High",
    impact: "High",
    stepRoles: ["Directory traversal reads server files outside web root"],
  },
  {
    id: "S-005",
    title: "XSS-based Account Compromise",
    objective: "Steal credentials or perform actions as the victim",
    requiredCategories: [["Cross-Site Scripting"], ["Security Headers"]],
    likelihood: "Medium",
    impact: "High",
    stepRoles: ["XSS payload executes in victim's browser", "Missing CSP header fails to block injected scripts"],
  },
  {
    id: "S-006",
    title: "Credential Exposure via Information Disclosure",
    objective: "Discover credentials or secrets in exposed files",
    requiredCategories: [["Information Disclosure"]],
    likelihood: "Medium",
    impact: "High",
    stepRoles: ["Exposed sensitive files (e.g. .env, .git/config) reveal credentials or internal configuration"],
  },
  {
    id: "S-007",
    title: "Man-in-the-Middle via Weak TLS",
    objective: "Intercept traffic between client and server",
    requiredCategories: [["TLS"]],
    likelihood: "Medium",
    impact: "High",
    stepRoles: ["Weak TLS configuration allows traffic interception or downgrade attacks"],
  },
  {
    id: "S-008",
    title: "Privilege Escalation via Mass Assignment",
    objective: "Escalate user privileges to admin via unprotected API fields",
    requiredCategories: [["Business Logic"]],
    likelihood: "Medium",
    impact: "High",
    stepRoles: ["Mass assignment vulnerability allows setting admin/role fields via API"],
  },
  {
    id: "S-009",
    title: "API Enumeration via GraphQL Introspection",
    objective: "Map the full API surface to identify attack vectors",
    requiredCategories: [["GraphQL"]],
    likelihood: "High",
    impact: "Medium",
    stepRoles: ["GraphQL introspection reveals all queries, mutations, and types"],
  },
  {
    id: "S-010",
    title: "Privilege Escalation via Broken Access Control",
    objective: "Access admin functionality using standard user credentials",
    requiredCategories: [["Authorization"]],
    likelihood: "High",
    impact: "High",
    stepRoles: ["Admin endpoint accessed using lower-privilege role credentials"],
  },
  {
    id: "S-011",
    title: "Data Theft via IDOR",
    objective: "Access another user's data by manipulating resource identifiers",
    requiredCategories: [["Authorization"], ["Information Disclosure"]],
    likelihood: "Medium",
    impact: "High",
    stepRoles: ["IDOR allows cross-user data access", "Exposed data reveals sensitive information"],
  },
];

export function analyzeAttackScenarios(findings: Pick<Finding, "category" | "title">[]): AttackScenario[] {
  const scenarios: AttackScenario[] = [];
  const categoryFindings = new Map<string, string[]>();
  for (const f of findings) {
    const existing = categoryFindings.get(f.category);
    if (existing) existing.push(f.title);
    else categoryFindings.set(f.category, [f.title]);
  }

  for (const template of SCENARIO_TEMPLATES) {
    const matchedSteps: { findingTitle: string; role: string }[] = [];
    let allMatched = true;

    for (let i = 0; i < template.requiredCategories.length; i++) {
      const alts = template.requiredCategories[i];
      let found = false;
      for (const cat of alts) {
        const catFindings = categoryFindings.get(cat);
        if (catFindings && catFindings.length > 0) {
          matchedSteps.push({ findingTitle: catFindings[0], role: template.stepRoles[i] });
          found = true;
          break;
        }
      }
      if (!found) { allMatched = false; break; }
    }

    if (allMatched && matchedSteps.length > 0) {
      scenarios.push({
        id: template.id,
        title: template.title,
        objective: template.objective,
        steps: matchedSteps,
        likelihood: template.likelihood,
        impact: template.impact,
      });
    }
  }

  return scenarios;
}

// ─── Score Calculator ─────────────────────────────────────────────────────────
// Cap how many findings per severity count toward the score so many mediums don't force 0/100.
const SCORE_CAP: Record<Finding["severity"], { deduction: number; maxCount: number }> = {
  critical: { deduction: 22, maxCount: 2 },
  high: { deduction: 12, maxCount: 3 },
  medium: { deduction: 5, maxCount: 6 },
  low: { deduction: 2, maxCount: 5 },
  info: { deduction: 0.5, maxCount: 5 },
};

// ─── SCA / Dependency Scanning ────────────────────────────────────────────────

export type ManifestType = "pom.xml" | "build.gradle" | "package.json" | "package-lock.json" |
  "requirements.txt" | "Pipfile.lock" | "go.mod" | "Gemfile.lock";

const MANIFEST_ECOSYSTEM: Record<string, string> = {
  "pom.xml": "Maven", "build.gradle": "Maven",
  "package.json": "npm", "package-lock.json": "npm",
  "requirements.txt": "PyPI", "Pipfile.lock": "PyPI",
  "go.mod": "Go", "Gemfile.lock": "RubyGems",
};

export interface ScaDependencyVuln {
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  cve: string;
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
}

/** Parse OSV-Scanner JSON output into structured vulnerability findings */
export function parseOsvOutput(jsonStr: string): ScaDependencyVuln[] {
  const vulns: ScaDependencyVuln[] = [];
  try {
    const data = JSON.parse(jsonStr);
    const results = data.results ?? [];
    for (const result of results) {
      for (const pkg of result.packages ?? []) {
        const pkgInfo = pkg.package ?? {};
        const pkgName = pkgInfo.name ?? "unknown";
        const pkgVersion = pkgInfo.version ?? "unknown";
        for (const vuln of pkg.vulnerabilities ?? []) {
          const id = vuln.aliases?.find((a: string) => a.startsWith("CVE-")) ?? vuln.id ?? "UNKNOWN";
          const severity = vuln.database_specific?.severity?.toLowerCase() ??
            (vuln.severity?.[0]?.score >= 9.0 ? "critical" : vuln.severity?.[0]?.score >= 7.0 ? "high" :
              vuln.severity?.[0]?.score >= 4.0 ? "medium" : "low");
          const fixed = vuln.affected?.[0]?.ranges?.[0]?.events?.find((e: any) => e.fixed)?.fixed ?? null;
          vulns.push({
            package: pkgName,
            installedVersion: pkgVersion,
            fixedVersion: fixed,
            cve: id,
            severity: severity as ScaDependencyVuln["severity"],
            summary: vuln.summary ?? vuln.details?.substring(0, 200) ?? `Vulnerability ${id}`,
          });
        }
      }
    }
  } catch {
    // malformed output
  }
  return vulns;
}

/** Parse Trivy JSON output into structured vulnerability findings */
export function parseTrivyOutput(jsonStr: string): ScaDependencyVuln[] {
  const vulns: ScaDependencyVuln[] = [];
  try {
    const data = JSON.parse(jsonStr);
    const results = data.Results ?? [];
    for (const result of results) {
      for (const v of result.Vulnerabilities ?? []) {
        const severity = (v.Severity ?? "MEDIUM").toLowerCase();
        vulns.push({
          package: v.PkgName ?? "unknown",
          installedVersion: v.InstalledVersion ?? "unknown",
          fixedVersion: v.FixedVersion ?? null,
          cve: v.VulnerabilityID ?? "UNKNOWN",
          severity: severity === "critical" ? "critical" : severity === "high" ? "high" : severity === "medium" ? "medium" : "low",
          summary: v.Title ?? v.Description?.substring(0, 200) ?? `Vulnerability ${v.VulnerabilityID}`,
        });
      }
    }
  } catch {
    // malformed output
  }
  return vulns;
}

/** Convert SCA vulnerabilities into scan findings */
export function scaVulnsToFindings(vulns: ScaDependencyVuln[], ecosystem: string): Finding[] {
  return vulns.map((v) => ({
    category: "SCA",
    severity: v.severity,
    title: `Vulnerable Dependency: ${v.package} ${v.installedVersion} (${v.cve})`,
    description: `${v.summary}. Ecosystem: ${ecosystem}.${v.fixedVersion ? ` Upgrade to ${v.fixedVersion} or later.` : " No fixed version available."}`,
    evidence: `Package: ${v.package}\nInstalled: ${v.installedVersion}\nFixed: ${v.fixedVersion ?? "N/A"}\nCVE: ${v.cve}`,
    recommendation: v.fixedVersion
      ? `Upgrade ${v.package} to version ${v.fixedVersion} or later.`
      : `Review ${v.package} ${v.installedVersion} for alternative packages or mitigations.`,
    cweId: "CWE-1104",
    owaspCategory: "A06:2021 – Vulnerable and Outdated Components",
  }));
}

/** Run SCA scanning using osv-scanner or trivy on a manifest file */
async function testSCA(scanId: number, manifestPath: string): Promise<Finding[]> {
  const fs = await import("fs");
  if (!fs.existsSync(manifestPath)) {
    await log(scanId, "warn", `SCA manifest not found: ${manifestPath}`, "sca");
    return [];
  }

  const basename = manifestPath.split("/").pop() ?? "";
  const ecosystem = MANIFEST_ECOSYSTEM[basename] ?? "Unknown";
  await log(scanId, "info", `SCA scanning ${basename} (${ecosystem} ecosystem)`, "sca");

  // Try OSV-Scanner first, then Trivy
  const scanners = [
    { name: "osv-scanner", cmd: `osv-scanner --json --lockfile=${manifestPath}`, parser: parseOsvOutput },
    { name: "trivy", cmd: `trivy fs --format json --scanners vuln ${manifestPath}`, parser: parseTrivyOutput },
  ];

  for (const scanner of scanners) {
    try {
      const { execSync } = await import("child_process");
      try {
        execSync(`which ${scanner.name}`, { stdio: "ignore", encoding: "utf8" });
      } catch {
        await log(scanId, "info", `${scanner.name} not found, trying next scanner...`, "sca");
        continue;
      }

      await log(scanId, "info", `Running ${scanner.name} on ${basename}...`, "sca");
      const { stdout, stderr, code } = await execCapture(scanner.cmd, {
        timeout: 120000, encoding: "utf8", maxBuffer: 4 * 1024 * 1024,
      });

      const output = stdout || stderr || "";
      const vulns = scanner.parser(output);
      await log(scanId, "info", `${scanner.name} found ${vulns.length} vulnerable dependencies`, "sca");

      if (vulns.length === 0) {
        await log(scanId, "success", "SCA scan: PASS — no vulnerable dependencies found", "sca");
        return [];
      }

      return scaVulnsToFindings(vulns, ecosystem);
    } catch (err: any) {
      await log(scanId, "warn", `${scanner.name} error: ${err.message}`, "sca");
    }
  }

  await log(scanId, "warn", "No SCA scanner available (install osv-scanner or trivy)", "sca");
  return [{
    category: "Tool Availability",
    severity: "info",
    title: "SCA scanner not available",
    description: "Neither osv-scanner nor trivy is installed. Dependency vulnerability scanning was skipped.",
    recommendation: "Install osv-scanner (npm i -g @google/osv-scanner) or trivy for SCA capability.",
  }];
}

// ─── Authenticated Multi-Role Scanning ───────────────────────────────────────

const AUTH_ADMIN_ENDPOINTS = [
  "/api/admin", "/api/admin/users", "/api/admin/settings", "/api/admin/config",
  "/api/users", "/api/roles", "/api/permissions", "/api/system",
  "/admin", "/admin/dashboard", "/management", "/api/management",
  "/api/v1/admin", "/api/v2/admin",
];

const AUTH_RESOURCE_PATTERNS = [
  "/api/users/{id}", "/api/orders/{id}", "/api/documents/{id}",
  "/api/profiles/{id}", "/api/accounts/{id}", "/api/data/{id}",
];

/** Test vertical privilege escalation: attempt admin-level endpoints with lower-privilege profiles */
export async function testVerticalEscalation(
  scanId: number,
  targetUrl: string,
  profiles: AuthProfile[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", "Testing for vertical privilege escalation", "auth-roles");

  const sorted = [...profiles].sort((a, b) => profilePrivilegeRank(a) - profilePrivilegeRank(b));
  const highPriv = sorted.filter((p) => profilePrivilegeRank(p) >= 3);
  const lowPriv = sorted.filter((p) => profilePrivilegeRank(p) < 3);

  if (highPriv.length === 0 || lowPriv.length === 0) {
    await log(scanId, "info", "Insufficient role diversity for vertical escalation test (need both admin-level and user-level profiles)", "auth-roles");
    return findings;
  }

  for (const endpoint of AUTH_ADMIN_ENDPOINTS) {
    for (const admin of highPriv) {
      let adminStatus: number;
      try {
        const resp = await httpGet(targetUrl, endpoint, { headers: buildAuthHeader(admin), timeout: 5000 });
        adminStatus = resp.status;
      } catch {
        continue;
      }

      if (adminStatus >= 400) continue;

      for (const user of lowPriv) {
        try {
          const resp = await httpGet(targetUrl, endpoint, { headers: buildAuthHeader(user), timeout: 5000 });

          if (resp.status < 400) {
            const title = `Vertical Privilege Escalation — ${endpoint} accessible as ${user.name}`;
            findings.push({
              category: "Authorization",
              severity: "high",
              title,
              description: `The endpoint ${endpoint} (expected: ${admin.name}-level) returned HTTP ${resp.status} when accessed as ${user.name}. This may allow privilege escalation.`,
              evidence: `Admin (${admin.name}): ${adminStatus}\nLow-priv (${user.name}): ${resp.status}\nResponse snippet: ${resp.body.substring(0, 200)}`,
              recommendation: "Implement server-side role checks on all privileged endpoints. Do not rely on client-side UI restrictions.",
              cweId: "CWE-269",
              owaspCategory: "A01:2021 – Broken Access Control",
              discoveredAs: user.name,
              exploitableAs: user.name,
              requiredLevel: admin.name,
              authEndpoint: `GET ${endpoint}`,
              poc: {
                curlCommand: `curl -H "${Object.entries(buildAuthHeader(user)).map(([k, v]) => `${k}: ${v}`).join("; ")}" ${targetUrl}${endpoint}`,
                requestRaw: `GET ${endpoint} HTTP/1.1\nHost: ${new URL(targetUrl).host}\n${Object.entries(buildAuthHeader(user)).map(([k, v]) => `${k}: ${v}`).join("\n")}`,
                responseSnippet: `HTTP ${resp.status}\n${resp.body.substring(0, 300)}`,
                reproductionSteps: [
                  `Authenticate as ${user.name} (${user.type} auth)`,
                  `Send GET request to ${endpoint}`,
                  `Observe HTTP ${resp.status} response — endpoint is accessible at lower privilege`,
                ],
              },
            });
            await log(scanId, "warn", `VULN: ${title}`, "auth-roles");
          }
        } catch {
          // endpoint not reachable with this profile
        }
      }
    }
  }

  if (findings.length === 0) {
    await log(scanId, "success", "Vertical escalation checks: PASS — no escalation detected", "auth-roles");
  }

  return findings;
}

/** Test horizontal privilege escalation (IDOR): access resources owned by one user as another */
export async function testHorizontalEscalation(
  scanId: number,
  targetUrl: string,
  profiles: AuthProfile[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", "Testing for horizontal privilege escalation (IDOR)", "auth-roles");

  const userProfiles = profiles.filter((p) => {
    const rank = profilePrivilegeRank(p);
    return rank >= 1 && rank <= 2;
  });

  if (userProfiles.length < 2) {
    await log(scanId, "info", "Insufficient user-level profiles for horizontal escalation test (need at least 2)", "auth-roles");
    return findings;
  }

  const testIds = ["1", "2", "100", "999"];

  for (const pattern of AUTH_RESOURCE_PATTERNS) {
    for (const id of testIds) {
      const endpoint = pattern.replace("{id}", id);
      const profileA = userProfiles[0];
      const profileB = userProfiles[1];

      try {
        const respA = await httpGet(targetUrl, endpoint, { headers: buildAuthHeader(profileA), timeout: 5000 });
        if (respA.status >= 400) continue;

        const respB = await httpGet(targetUrl, endpoint, { headers: buildAuthHeader(profileB), timeout: 5000 });

        if (respB.status < 400 && respB.body.length > 0) {
          const sameContent = respA.body.trim() === respB.body.trim();
          if (sameContent) {
            const title = `Horizontal Privilege Escalation — ${endpoint} accessible across users`;
            findings.push({
              category: "Authorization",
              severity: "high",
              title,
              description: `The resource at ${endpoint} returns identical data for ${profileA.name} and ${profileB.name}, suggesting missing ownership checks (IDOR).`,
              evidence: `${profileA.name} response: ${respA.status} (${respA.body.substring(0, 100)})\n${profileB.name} response: ${respB.status} (${respB.body.substring(0, 100)})`,
              recommendation: "Enforce resource ownership checks server-side. Verify the authenticated user owns or has been granted access to each requested resource.",
              cweId: "CWE-639",
              owaspCategory: "A01:2021 – Broken Access Control",
              discoveredAs: profileB.name,
              exploitableAs: profileB.name,
              requiredLevel: profileA.name,
              authEndpoint: `GET ${endpoint}`,
            });
            await log(scanId, "warn", `VULN: ${title}`, "auth-roles");
            break;
          }
        }
      } catch {
        // endpoint not reachable
      }
    }
  }

  if (findings.length === 0) {
    await log(scanId, "success", "Horizontal escalation checks: PASS — no IDOR detected", "auth-roles");
  }

  return findings;
}

/** Test session handling: token expiry, logout invalidation */
export async function testSessionHandling(
  scanId: number,
  targetUrl: string,
  profiles: AuthProfile[],
  config: AuthTestConfig,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", "Testing session/token handling", "auth-roles");

  const authProfiles = profiles.filter((p) => p.type !== "none" && p.token);

  for (const profile of authProfiles) {
    const headers = buildAuthHeader(profile);

    if (config.tokenReuse) {
      try {
        const logoutPaths = ["/api/auth/logout", "/api/logout", "/logout", "/api/v1/auth/logout"];
        for (const logoutPath of logoutPaths) {
          try {
            await httpGet(targetUrl, logoutPath, { method: "POST", headers, timeout: 5000 });
          } catch {
            continue;
          }

          const postLogout = await httpGet(targetUrl, "/api/users", { headers, timeout: 5000 });
          if (postLogout.status < 400) {
            findings.push({
              category: "Authorization",
              severity: "medium",
              title: `Token still valid after logout — ${profile.name}`,
              description: `The bearer token for ${profile.name} remains valid after calling ${logoutPath}. This allows session reuse after logout.`,
              evidence: `POST ${logoutPath}: completed\nGET /api/users with same token: ${postLogout.status}`,
              recommendation: "Invalidate tokens server-side on logout. Use a token blocklist or short-lived JWTs with refresh tokens.",
              cweId: "CWE-284",
              owaspCategory: "A07:2021 – Identification and Authentication Failures",
              discoveredAs: profile.name,
              authEndpoint: logoutPath,
            });
            await log(scanId, "warn", `Token reuse after logout detected for ${profile.name}`, "auth-roles");
            break;
          }
        }
      } catch {
        // skip
      }
    }

    if (config.sessionExpiry) {
      try {
        const resp = await httpGet(targetUrl, "/api/users", { headers, timeout: 5000 });
        if (resp.status < 400) {
          const authzHeader = resp.headers["www-authenticate"] ?? "";
          const cacheControl = resp.headers["cache-control"] ?? "";
          if (!cacheControl.includes("no-store") && !cacheControl.includes("no-cache")) {
            findings.push({
              category: "Authorization",
              severity: "low",
              title: `Missing cache controls on authenticated endpoint — ${profile.name}`,
              description: "Authenticated responses lack Cache-Control: no-store, which may allow cached credential data.",
              evidence: `Cache-Control: ${cacheControl || "(not set)"}`,
              recommendation: "Set Cache-Control: no-store on all authenticated API responses.",
              cweId: "CWE-284",
              owaspCategory: "A07:2021 – Identification and Authentication Failures",
              discoveredAs: profile.name,
            });
          }
        }
      } catch {
        // skip
      }
    }
  }

  if (findings.length === 0) {
    await log(scanId, "success", "Session handling checks: PASS", "auth-roles");
  }

  return findings;
}

/** Run all authenticated multi-role scanning tests */
export async function testAuthenticatedAccess(
  scanId: number,
  targetUrl: string,
  authConfig: AuthScanConfig,
): Promise<Finding[]> {
  const profiles = authConfig.authProfiles ?? [];
  const tests = authConfig.authTests ?? {};
  const findings: Finding[] = [];

  if (profiles.length === 0) {
    await log(scanId, "info", "No auth profiles configured — skipping authenticated scanning", "auth-roles");
    return findings;
  }

  await log(scanId, "info", `Auth profiles: ${profiles.map((p) => `${p.name} (${p.type})`).join(", ")}`, "auth-roles");

  if (tests.verticalEscalation !== false) {
    findings.push(...await testVerticalEscalation(scanId, targetUrl, profiles));
  }

  if (tests.horizontalEscalation !== false) {
    findings.push(...await testHorizontalEscalation(scanId, targetUrl, profiles));
  }

  if (tests.sessionExpiry || tests.tokenReuse) {
    findings.push(...await testSessionHandling(scanId, targetUrl, profiles, tests));
  }

  return findings;
}

/** Exported for unit tests. */
export function calculateScore(findings: Pick<Finding, "severity">[]): { score: number; riskLevel: "critical" | "high" | "medium" | "low" | "info" } {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let deductions = 0;
  for (const f of findings) {
    const cap = SCORE_CAP[f.severity];
    if (counts[f.severity] >= cap.maxCount) continue;
    counts[f.severity]++;
    deductions += cap.deduction;
  }
  const score = Math.round(Math.max(0, Math.min(100, 100 - deductions)));
  let riskLevel: "critical" | "high" | "medium" | "low" | "info" = "info";
  if (score < 40) riskLevel = "critical";
  else if (score < 60) riskLevel = "high";
  else if (score < 75) riskLevel = "medium";
  else if (score < 90) riskLevel = "low";
  return { score, riskLevel };
}

// ─── Trend Reporting ──────────────────────────────────────────────────────────
export interface TrendSummary {
  previousScanId: number;
  previousScanDate: string;
  newFindings: number;
  resolvedFindings: number;
  persistingFindings: number;
  newItems: string[];
  resolvedItems: string[];
  persistingItems: string[];
}

export function computeTrend(
  currentFindings: Pick<Finding, "title" | "category" | "severity">[],
  previousFindings: { title: string; category: string; severity: string }[],
  previousScan: { id: number; completedAt: Date | null }
): TrendSummary {
  const prevSet = new Set(previousFindings.map((f) => `${f.category}::${f.title}`));
  const currSet = new Set(currentFindings.map((f) => `${f.category}::${f.title}`));

  const newItems: string[] = [];
  const persistingItems: string[] = [];
  const resolvedItems: string[] = [];

  for (const f of currentFindings) {
    const key = `${f.category}::${f.title}`;
    if (prevSet.has(key)) {
      if (!persistingItems.includes(f.title)) persistingItems.push(f.title);
    } else {
      if (!newItems.includes(f.title)) newItems.push(f.title);
    }
  }

  for (const f of previousFindings) {
    const key = `${f.category}::${f.title}`;
    if (!currSet.has(key)) {
      if (!resolvedItems.includes(f.title)) resolvedItems.push(f.title);
    }
  }

  return {
    previousScanId: previousScan.id,
    previousScanDate: previousScan.completedAt?.toISOString().slice(0, 10) ?? "unknown",
    newFindings: newItems.length,
    resolvedFindings: resolvedItems.length,
    persistingFindings: persistingItems.length,
    newItems,
    resolvedItems,
    persistingItems,
  };
}

// ─── Main Scan Runner ─────────────────────────────────────────────────────────
export async function runScan(
  scanId: number,
  targetId: number,
  targetUrl: string,
  toolList: string[],
  scanMode: ScanMode = "light",
  authConfig?: AuthScanConfig,
  manifestPath?: string,
): Promise<void> {
  await log(scanId, "info", `=== PenTest Portal Scan Started ===`, "init");
  await log(scanId, "info", `Target: ${targetUrl}`, "init");
  await log(scanId, "info", `Mode: ${scanMode.toUpperCase()}`, "init");
  await log(scanId, "info", `Tools: ${toolList.join(", ")}`, "init");
  await log(scanId, "info", `Scan ID: ${scanId}`, "init");

  await updateScan(scanId, { status: "running", startedAt: new Date() });

  const allFindings: Finding[] = [];

  // Full mode: add extra tools (cors, traversal, config) and external tools (nikto, nuclei, zap)
  const toolsToRun = Array.from(new Set(toolList.map((t) => t.toLowerCase().trim())));
  if (scanMode === "full") {
    for (const t of ["cors", "traversal", "config", "logic", "graphql", "ssrf", "tls", "auth-roles", "sca", "nikto", "nuclei", "wapiti", "zap"]) {
      if (!toolsToRun.includes(t)) toolsToRun.push(t);
    }
  }

  try {
    // Run each selected tool
    for (const tool of toolsToRun) {
      await log(scanId, "info", `\n─── Starting ${tool.toUpperCase()} scan ───`, tool);

      let toolFindings: Finding[] = [];

      switch (tool.toLowerCase()) {
        case "headers":
          toolFindings = await testSecurityHeaders(scanId, targetUrl);
          break;
        case "auth":
          toolFindings = await testAuthentication(scanId, targetUrl, scanMode);
          break;
        case "sqli":
          toolFindings = await testSQLInjection(scanId, targetUrl, scanMode);
          break;
        case "xss":
          toolFindings = await testXSS(scanId, targetUrl, scanMode);
          break;
        case "recon":
          toolFindings = await testIntelligenceGathering(scanId, targetUrl, scanMode);
          break;
        case "cors":
          toolFindings = await testCORS(scanId, targetUrl);
          break;
        case "traversal":
          toolFindings = await testDirectoryTraversal(scanId, targetUrl);
          break;
        case "config":
          toolFindings = await testHTTPMethods(scanId, targetUrl);
          break;
        case "logic":
          toolFindings = await testBusinessLogic(scanId, targetUrl);
          break;
        case "graphql":
          toolFindings = await testGraphQL(scanId, targetUrl);
          break;
        case "ssrf":
          toolFindings = await testSSRF(scanId, targetUrl);
          break;
        case "tls":
          toolFindings = await testSSLTLS(scanId, targetUrl);
          break;
        case "auth-roles":
          if (authConfig && authConfig.authProfiles && authConfig.authProfiles.length > 0) {
            toolFindings = await testAuthenticatedAccess(scanId, targetUrl, authConfig);
          } else {
            await log(scanId, "info", "Auth-roles scan skipped: no auth profiles configured", "auth-roles");
          }
          break;
        case "sca":
          if (manifestPath) {
            toolFindings = await testSCA(scanId, manifestPath);
          } else {
            await log(scanId, "info", "SCA scan skipped: no manifest path provided (use --deps flag)", "sca");
          }
          break;
        case "nikto": {
          await log(scanId, "info", "Nikto scan: checking if nikto is available...", "nikto");
          const { execSync } = await import("child_process");
          const { existsSync } = await import("fs");
          // Prefer full paths so scans work when PATH is minimal (e.g. systemd)
          const niktoPaths = ["/usr/local/bin/nikto", "/usr/bin/nikto", "nikto"];
          let niktoCmd = niktoPaths.find((p) => {
            if (p === "nikto") {
              try {
                execSync("which nikto", { stdio: "ignore", encoding: "utf8" });
                return true;
              } catch {
                return false;
              }
            }
            return existsSync(p);
          }) ?? "nikto";
          let niktoAvailable = false;
          try {
            execSync(`${niktoCmd} -Version`, { stdio: "ignore", encoding: "utf8" });
            niktoAvailable = true;
            await log(scanId, "info", "Nikto found — running scan (up to 3 minutes; no further logs until it finishes)...", "nikto");
            const niktoExtra = scanMode === "full" ? "-C all -maxtime 180" : "";
            const niktoOpts = `-Format txt -nointeractive ${niktoExtra}`.trim();
            const execOpts = {
              timeout: 200000,
              encoding: "utf8" as const,
              maxBuffer: 4 * 1024 * 1024,
              env: { ...process.env, PERL_LWP_SSL_VERIFY_HOSTNAME: "0" } as NodeJS.ProcessEnv,
            };
            let output = "";
            try {
              const { stdout, stderr, code } = await execCapture(
                `${niktoCmd} -h ${targetUrl} ${niktoOpts} 2>&1`,
                execOpts
              );
              output = (stdout || stderr || "").trim();
              if (code !== 0 && output) {
                await log(scanId, "info", "Nikto completed (non-zero exit often indicates findings; output above).", "nikto");
              }
            } catch (runErr: unknown) {
              const e = runErr as { stdout?: string; stderr?: string };
              output = e?.stdout ?? e?.stderr ?? "";
              if (output) {
                await log(scanId, "info", "Nikto completed (some scanners exit non-zero when findings are present; output above was captured).", "nikto");
              } else {
                throw runErr;
              }
            }
            if (output) {
              await log(scanId, "info", output.substring(0, 2000), "nikto");
              const niktoLines = output.split("\n").filter((l) => l.includes("OSVDB") || l.includes("+ "));
              for (const line of niktoLines.slice(0, 50)) {
                if (line.trim().startsWith("+")) {
                  toolFindings.push({
                    category: "Nikto",
                    severity: "medium",
                    title: line.trim().substring(0, 200),
                    description: line.trim(),
                    recommendation: "Review and remediate the identified issue.",
                  });
                }
              }
            }
          } catch (err) {
            if (!niktoAvailable) {
              await log(scanId, "warn", "Nikto not installed. Install to /opt/nikto and symlink to /usr/local/bin/nikto.", "nikto");
              toolFindings.push({
                category: "Tool Availability",
                severity: "info",
                title: "Nikto scanner not available",
                description: "Nikto is not installed on the scan server. Install it to enable web server vulnerability scanning.",
                recommendation: "Clone https://github.com/sullo/nikto to /opt/nikto and add a nikto wrapper in /usr/local/bin.",
              });
            } else {
              const msg = (err as Error).message;
              const friendlyMsg = msg.startsWith("Command failed:") && msg.includes("nikto")
                ? "Nikto scan failed (timeout or command error). If Nikto produced output, check the log above."
                : `Nikto scan failed (timeout or error): ${msg}`;
              await log(scanId, "warn", friendlyMsg, "nikto");
            }
          }
          break;
        }
        case "nuclei": {
          await log(scanId, "info", "Nuclei scan: checking if nuclei is available...", "nuclei");
          const { execSync } = await import("child_process");
          const { existsSync } = await import("fs");
          const nucleiPaths = ["/usr/local/bin/nuclei", "/usr/bin/nuclei", "nuclei"];
          const nucleiCmd =
            nucleiPaths.find((p) => {
              if (p === "nuclei") {
                try {
                  execSync("which nuclei", { stdio: "ignore", encoding: "utf8" });
                  return true;
                } catch {
                  return false;
                }
              }
              return existsSync(p);
            }) ?? "nuclei";
          let nucleiAvailable = false;
          try {
            try {
              execSync(`${nucleiCmd} -version`, { stdio: "ignore", encoding: "utf8", timeout: 5000 });
              nucleiAvailable = true;
            } catch {
              if (nucleiCmd.startsWith("/") && existsSync(nucleiCmd)) nucleiAvailable = true;
            }
            if (!nucleiAvailable) throw new Error("Nuclei not found");
            await log(scanId, "info", "Nuclei found — running template scan (up to 5 minutes; low/medium/high/critical + CVE/misconfig tags)...", "nuclei");
            let output = "";
            const nucleiSeverity = scanMode === "full" ? "low,medium,high,critical" : "medium,high,critical";
            const nucleiTags = scanMode === "full" ? "-tags cve,misconfig,exposure,takeover" : "";
            try {
              const result = await execAsync(`${nucleiCmd} -u ${targetUrl} -severity ${nucleiSeverity} ${nucleiTags} -silent 2>&1`.trim(), {
                timeout: 300000,
                encoding: "utf8",
                maxBuffer: 4 * 1024 * 1024,
              });
              const res = result as { stdout?: string } | [string, string];
              output = Array.isArray(res) ? (res[0] ?? "") : (res.stdout ?? "");
            } catch (runErr: unknown) {
              const e = runErr as { stdout?: string; stderr?: string; message?: string };
              output = e?.stdout ?? e?.stderr ?? "";
              if (output) {
                await log(scanId, "info", "Nuclei completed (some scanners exit non-zero when findings are present; output above was captured).", "nuclei");
              }
            }
            if (output) {
              const lines = output.split("\n").filter((l) => l.trim());
              for (const line of lines.slice(0, 30)) {
                const severityMatch = line.match(/\[(critical|high|medium|low|info)\]/i);
                const sev = (severityMatch?.[1]?.toLowerCase() as Finding["severity"]) || "medium";
                toolFindings.push({
                  category: "Nuclei",
                  severity: sev,
                  title: line.substring(0, 200),
                  description: line,
                  recommendation: "Review and remediate the identified vulnerability.",
                });
              }
              await log(scanId, "info", `Nuclei found ${toolFindings.length} findings`, "nuclei");
            }
          } catch {
            if (!nucleiAvailable) {
              await log(scanId, "warn", "Nuclei not installed. Install to /usr/local/bin/nuclei or see https://github.com/projectdiscovery/nuclei", "nuclei");
              toolFindings.push({
                category: "Tool Availability",
                severity: "info",
                title: "Nuclei scanner not available",
                description: "Nuclei is not installed on the scan server.",
                recommendation: "Install Nuclei: download from https://github.com/projectdiscovery/nuclei/releases and place nuclei in /usr/local/bin.",
              });
            } else {
              await log(scanId, "warn", "Nuclei scan failed (timeout or error).", "nuclei");
            }
          }
          break;
        }
        case "wapiti": {
          await log(scanId, "info", "Wapiti scan: checking if wapiti is available...", "wapiti");
          const { execSync } = await import("child_process");
          const { existsSync } = await import("fs");
          const { readFile } = await import("fs/promises");
          const wapitiPaths = ["/usr/local/bin/wapiti", "/usr/local/bin/wapiti3", "/usr/bin/wapiti", "/usr/bin/wapiti3", "wapiti", "wapiti3"];
          const wapitiCmd = wapitiPaths.find((p) => {
            if (p === "wapiti" || p === "wapiti3") {
              try {
                execSync(`which ${p}`, { stdio: "ignore", encoding: "utf8" });
                return true;
              } catch {
                return false;
              }
            }
            return existsSync(p);
          });
          if (!wapitiCmd) {
            await log(scanId, "info", "Wapiti not installed (optional). Install: pip install wapiti3", "wapiti");
            break;
          }
          const wapitiOut = `/tmp/wapiti-${scanId}.json`;
          try {
            await log(scanId, "info", "Wapiti found — running crawl + modules (up to 5 minutes)...", "wapiti");
            await execAsync(`${wapitiCmd} -u ${targetUrl} -f json -o ${wapitiOut} -v 0 --scope domain`, {
              timeout: 300000,
              encoding: "utf8",
              maxBuffer: 8 * 1024 * 1024,
            });
            const raw = await readFile(wapitiOut, "utf8").catch(() => "{}");
            const data = JSON.parse(raw) as Record<string, unknown>;
            const vulns = (data?.vulnerabilities ?? data?.flaws ?? data?.vulns) as Record<string, { severity?: number; desc?: string; name?: string; title?: string }[]> | undefined;
            if (vulns && typeof vulns === "object" && !Array.isArray(vulns)) {
              for (const [name, items] of Object.entries(vulns)) {
                if (!Array.isArray(items)) continue;
                for (const v of items.slice(0, 10)) {
                  const severity = (v.severity === 3 ? "high" : v.severity === 2 ? "medium" : "low") as Finding["severity"];
                  toolFindings.push({
                    category: "Wapiti",
                    severity,
                    title: (v.name ?? v.title ?? name) as string,
                    description: (v.desc ?? v.name ?? name) as string,
                    recommendation: "Review and remediate the reported issue.",
                  });
                }
              }
            }
            await log(scanId, "info", `Wapiti found ${toolFindings.length} finding(s)`, "wapiti");
          } catch (err) {
            await log(scanId, "warn", `Wapiti scan failed or not installed: ${(err as Error).message}`, "wapiti");
          }
          break;
        }
        case "zap":
          await log(scanId, "info", "OWASP ZAP scan: checking if zap is available...", "zap");
          try {
            const { execSync } = await import("child_process");
            execSync("which zap.sh || which zap-cli", { stdio: "ignore" });
            await log(scanId, "info", "ZAP found — running baseline scan (up to 5 minutes; no further logs until it finishes)...", "zap");
            const { stdout } = await execAsync(`zap-baseline.py -t ${targetUrl} -J /tmp/zap-report.json 2>&1 || zap.sh -cmd -quickurl ${targetUrl} 2>&1`, {
              timeout: 300000,
              encoding: "utf8",
              maxBuffer: 4 * 1024 * 1024,
            });
            const output = stdout ?? "";
            await log(scanId, "info", output.substring(0, 2000), "zap");
            toolFindings.push({
              category: "OWASP ZAP",
              severity: "info",
              title: "ZAP baseline scan completed",
              description: "OWASP ZAP baseline scan completed. Review the full output for detailed findings.",
              evidence: output.substring(0, 500),
              recommendation: "Review ZAP report for detailed vulnerability information.",
            });
          } catch {
            await log(scanId, "warn", "OWASP ZAP not installed or scan failed. Install from: https://www.zaproxy.org/", "zap");
            toolFindings.push({
              category: "Tool Availability",
              severity: "info",
              title: "OWASP ZAP not available",
              description: "OWASP ZAP is not installed on the scan server.",
              recommendation: "Install OWASP ZAP from https://www.zaproxy.org/download/",
            });
          }
          break;
        default:
          await log(scanId, "warn", `Unknown tool: ${tool}`, tool);
      }

      allFindings.push(...toolFindings);
      await log(scanId, "info", `${tool.toUpperCase()} complete: ${toolFindings.length} finding(s)`, tool);
    }

    // Calculate score
    const { score, riskLevel } = calculateScore(allFindings);

    // Count by severity
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of allFindings) counts[f.severity]++;

    // Store findings (with CVSS, business impact, remediation, ATT&CK, ISO enrichment)
    if (allFindings.length > 0) {
      const dbFindings: InsertScanFinding[] = allFindings.map((f) => {
        const enriched = enrichFinding(f.category, f.severity, f.cweId);

        let evidence = f.evidence ?? "";
        if (f.discoveredAs || f.exploitableAs || f.requiredLevel || f.authEndpoint) {
          const authMeta: string[] = [];
          if (f.discoveredAs)  authMeta.push(`Discovered As: ${f.discoveredAs}`);
          if (f.exploitableAs) authMeta.push(`Exploitable As: ${f.exploitableAs}`);
          if (f.requiredLevel) authMeta.push(`Required Level: ${f.requiredLevel}`);
          if (f.authEndpoint)  authMeta.push(`Endpoint: ${f.authEndpoint}`);
          evidence = `[Auth Context] ${authMeta.join(" | ")}\n${evidence}`;
        }

        const poc = f.poc ?? null;

        return {
          scanId,
          category: f.category,
          severity: f.severity,
          title: f.title,
          description: f.description,
          evidence: evidence || null,
          recommendation: f.recommendation,
          cweId: f.cweId,
          owaspCategory: f.owaspCategory,
          cvssVector: enriched.cvssVector,
          cvssScore: enriched.cvssScore != null ? String(enriched.cvssScore) : null,
          remediationComplexity: enriched.remediationComplexity,
          remediationPriority: enriched.remediationPriority,
          businessImpact: enriched.businessImpact,
          attackTechniques: enriched.attackTechniques,
          iso27001Controls: enriched.iso27001Controls,
          poc,
          status: "open",
        };
      });
      await createFindings(dbFindings);
    }

    // Attack scenario chain analysis
    const scenarios = analyzeAttackScenarios(allFindings);
    if (scenarios.length > 0) {
      await log(scanId, "info", `Identified ${scenarios.length} attack scenario(s)`, "scenarios");
      for (const s of scenarios) {
        await log(scanId, "info", `  ${s.id}: ${s.title} (Likelihood: ${s.likelihood}, Impact: ${s.impact})`, "scenarios");
      }
    }

    // Trend analysis — compare against previous scan of same target
    let trendSummary: TrendSummary | null = null;
    try {
      const prevScan = await getPreviousCompletedScan(targetId, scanId);
      if (prevScan) {
        const prevFindings = await getFindingsByScan(prevScan.id);
        trendSummary = computeTrend(allFindings, prevFindings, prevScan);
        await log(scanId, "info", `Trend vs scan #${prevScan.id} (${prevScan.completedAt?.toISOString().slice(0, 10) ?? "unknown"}): ${trendSummary.newFindings} new, ${trendSummary.resolvedFindings} resolved, ${trendSummary.persistingFindings} persisting`, "trend");
      }
    } catch (trendErr: any) {
      await log(scanId, "warn", `Trend analysis skipped: ${trendErr.message}`, "trend");
    }

    // Update scan record
    await updateScan(scanId, {
      status: "completed",
      completedAt: new Date(),
      securityScore: score,
      riskLevel,
      totalFindings: allFindings.length,
      criticalCount: counts.critical,
      highCount: counts.high,
      mediumCount: counts.medium,
      lowCount: counts.low,
      infoCount: counts.info,
      scenarios: scenarios.length > 0 ? scenarios : null,
      trendSummary: trendSummary ?? undefined,
    });

    // Update target's lastScannedAt
    await updateTarget(targetId, { lastScannedAt: new Date() });

    await log(scanId, "success", `\n=== Scan Complete ===`, "complete");
    await log(scanId, "success", `Security Score: ${score}/100 | Risk Level: ${riskLevel.toUpperCase()}`, "complete");
    await log(scanId, "success", `Total Findings: ${allFindings.length} (Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low}, Info: ${counts.info})`, "complete");
    if (scenarios.length > 0) {
      await log(scanId, "success", `Attack Scenarios: ${scenarios.length} chain(s) identified`, "complete");
    }
    if (trendSummary) {
      await log(scanId, "success", `Trend: +${trendSummary.newFindings} new, -${trendSummary.resolvedFindings} resolved, ${trendSummary.persistingFindings} persisting`, "complete");
    }
  } catch (err: any) {
    await log(scanId, "error", `Scan failed: ${err.message}`, "error");
    await updateScan(scanId, {
      status: "failed",
      completedAt: new Date(),
      errorMessage: err.message,
    });
  }
}
