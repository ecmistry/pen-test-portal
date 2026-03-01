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
 *   nikto    — Nikto web server scanner (requires nikto installed)
 *   nuclei   — Nuclei vulnerability scanner (requires nuclei installed)
 *   zap      — OWASP ZAP baseline scan (requires zap.sh installed)
 */

import https from "https";
import http from "http";
import { URL } from "url";
import { appendScanLog, createFindings, updateScan, updateTarget } from "./db";
import { InsertScanFinding } from "../drizzle/schema";
import { getPenTestCache } from "./penTestUpdater";

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
          findings.push({
            category: "SQL Injection",
            severity: "critical",
            title: `SQL injection vulnerability detected at ${path}`,
            description: "The application returned a SQL error message in response to an injection payload, indicating it may be vulnerable to SQL injection.",
            evidence: `Payload: ${payload}\nPath: ${path}\nResponse snippet: ${resp.body.substring(0, 300)}`,
            recommendation: "Use parameterised queries or prepared statements. Never interpolate user input into SQL strings. Implement input validation.",
            cweId: "CWE-89",
            owaspCategory: "A03:2021 – Injection",
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
            findings.push({
              category: "SQL Injection",
              severity: "critical",
              title: `Time-based blind SQL injection at ${path}`,
              description: `Response delayed by ~${Math.round(elapsed / 1000)}s, indicating possible time-based SQL injection.`,
              evidence: `Payload: ${payload}\nPath: ${path}\nDelay: ${elapsed}ms`,
              recommendation: "Use parameterised queries. Time-based injection suggests blind SQLi is exploitable.",
              cweId: "CWE-89",
              owaspCategory: "A03:2021 – Injection",
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
          findings.push({
            category: "Cross-Site Scripting",
            severity: "high",
            title: `Reflected XSS vulnerability at ${path}`,
            description: "User-supplied input is reflected in the response without proper encoding, enabling cross-site scripting attacks.",
            evidence: `Payload: ${payload}\nPath: ${path}`,
            recommendation: "Encode all user-supplied data before rendering in HTML. Implement a strict Content-Security-Policy.",
            cweId: "CWE-79",
            owaspCategory: "A03:2021 – Injection",
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
/** Returns true if response looks like SPA fallback (index.html), not actual file content */
function isSpaFallback(body: string, contentType: string): boolean {
  const ct = (contentType || "").toLowerCase();
  if (ct.includes("text/html")) {
    const trimmed = body.trim().toLowerCase();
    return trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html");
  }
  return false;
}

/** Check if body contains file-specific content (real exposure vs SPA fallback) */
function hasFileSpecificContent(path: string, body: string): boolean {
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
async function testHTTPMethods(scanId: number, targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await log(scanId, "info", `Testing HTTP methods for ${targetUrl}`, "config");

  const methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT"];

  for (const method of methods) {
    try {
      const { status, headers, body } = await httpGet(targetUrl, "/", { method });
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

// ─── Score Calculator ─────────────────────────────────────────────────────────
function calculateScore(findings: Finding[]): { score: number; riskLevel: "critical" | "high" | "medium" | "low" | "info" } {
  let deductions = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical": deductions += 25; break;
      case "high": deductions += 15; break;
      case "medium": deductions += 8; break;
      case "low": deductions += 3; break;
      case "info": deductions += 1; break;
    }
  }
  const score = Math.max(0, 100 - deductions);
  let riskLevel: "critical" | "high" | "medium" | "low" | "info" = "info";
  if (score < 40) riskLevel = "critical";
  else if (score < 60) riskLevel = "high";
  else if (score < 75) riskLevel = "medium";
  else if (score < 90) riskLevel = "low";
  return { score, riskLevel };
}

// ─── Main Scan Runner ─────────────────────────────────────────────────────────
export async function runScan(
  scanId: number,
  targetId: number,
  targetUrl: string,
  toolList: string[],
  scanMode: ScanMode = "light"
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
    for (const t of ["cors", "traversal", "config", "nikto", "nuclei", "zap"]) {
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
        case "nikto":
          await log(scanId, "info", "Nikto scan: checking if nikto is available...", "nikto");
          try {
            const { execSync } = await import("child_process");
            execSync("which nikto", { stdio: "ignore" });
            await log(scanId, "info", "Nikto found — running scan (this may take several minutes)...", "nikto");
            const output = execSync(`nikto -h ${targetUrl} -Format txt -nointeractive 2>&1`, {
              timeout: 120000,
              encoding: "utf8",
            });
            await log(scanId, "info", output.substring(0, 2000), "nikto");
            // Parse Nikto output for findings
            const niktoLines = output.split("\n").filter((l) => l.includes("OSVDB") || l.includes("+ "));
            for (const line of niktoLines.slice(0, 20)) {
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
          } catch {
            await log(scanId, "warn", "Nikto not installed or scan failed. Install with: sudo apt-get install nikto", "nikto");
            toolFindings.push({
              category: "Tool Availability",
              severity: "info",
              title: "Nikto scanner not available",
              description: "Nikto is not installed on the scan server. Install it to enable web server vulnerability scanning.",
              recommendation: "Install Nikto: sudo apt-get install nikto",
            });
          }
          break;
        case "nuclei":
          await log(scanId, "info", "Nuclei scan: checking if nuclei is available...", "nuclei");
          try {
            const { execSync } = await import("child_process");
            execSync("which nuclei", { stdio: "ignore" });
            await log(scanId, "info", "Nuclei found — running template scan...", "nuclei");
            const output = execSync(`nuclei -u ${targetUrl} -severity medium,high,critical -silent 2>&1`, {
              timeout: 180000,
              encoding: "utf8",
            });
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
          } catch {
            await log(scanId, "warn", "Nuclei not installed or scan failed. Install from: https://github.com/projectdiscovery/nuclei", "nuclei");
            toolFindings.push({
              category: "Tool Availability",
              severity: "info",
              title: "Nuclei scanner not available",
              description: "Nuclei is not installed on the scan server.",
              recommendation: "Install Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            });
          }
          break;
        case "zap":
          await log(scanId, "info", "OWASP ZAP scan: checking if zap is available...", "zap");
          try {
            const { execSync } = await import("child_process");
            execSync("which zap.sh || which zap-cli", { stdio: "ignore" });
            await log(scanId, "info", "ZAP found — running baseline scan...", "zap");
            const output = execSync(`zap-baseline.py -t ${targetUrl} -J /tmp/zap-report.json 2>&1 || zap.sh -cmd -quickurl ${targetUrl} 2>&1`, {
              timeout: 300000,
              encoding: "utf8",
            });
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

    // Store findings
    if (allFindings.length > 0) {
      const dbFindings: InsertScanFinding[] = allFindings.map((f) => ({
        scanId,
        category: f.category,
        severity: f.severity,
        title: f.title,
        description: f.description,
        evidence: f.evidence,
        recommendation: f.recommendation,
        cweId: f.cweId,
        owaspCategory: f.owaspCategory,
        status: "open",
      }));
      await createFindings(dbFindings);
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
    });

    // Update target's lastScannedAt
    await updateTarget(targetId, { lastScannedAt: new Date() });

    await log(scanId, "success", `\n=== Scan Complete ===`, "complete");
    await log(scanId, "success", `Security Score: ${score}/100 | Risk Level: ${riskLevel.toUpperCase()}`, "complete");
    await log(scanId, "success", `Total Findings: ${allFindings.length} (Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low}, Info: ${counts.info})`, "complete");
  } catch (err: any) {
    await log(scanId, "error", `Scan failed: ${err.message}`, "error");
    await updateScan(scanId, {
      status: "failed",
      completedAt: new Date(),
      errorMessage: err.message,
    });
  }
}
