/**
 * Scan-result quality helpers: confidence, probe path merge, cross-tool dedupe keys.
 */

export type FindingConfidence = "confirmed" | "likely" | "heuristic";

export type ProbeTarget = {
  path: string;
  method?: string;
  /** Query/body param names to inject into */
  params?: string[];
  hasJsonBody?: boolean;
  /** application/json | application/x-www-form-urlencoded | multipart/form-data */
  contentType?: string;
  source?: "static" | "openapi" | "discovery" | "retest";
};

/** Normalize URL for correlation (keep param names, drop values, collapse numeric IDs) */
export function normalizeAffectedUrl(url?: string | null): string {
  if (!url) return "";
  try {
    const u = new URL(url, "https://normalize.local");
    u.hash = "";
    const path = u.pathname.replace(/\/\d+(?=\/|$)/g, "/{id}");
    const keys = Array.from(u.searchParams.keys())
      .map((k) => k.toLowerCase())
      .sort();
    const q = keys.length ? `?${keys.map((k) => `${k}=`).join("&")}` : "";
    return `${u.origin}${path}${q}`.toLowerCase();
  } catch {
    const raw = String(url).toLowerCase();
    const [pathPart, queryPart] = raw.split("?");
    if (!queryPart) return pathPart;
    const keys = queryPart
      .split("&")
      .map((p) => p.split("=")[0])
      .filter(Boolean)
      .sort();
    return keys.length ? `${pathPart}?${keys.map((k) => `${k}=`).join("&")}` : pathPart;
  }
}

/** Stable correlation key across tools (primary dedupe / trend / retest) */
export function normalizeFindingKey(f: {
  title: string;
  category?: string | null;
  cweId?: string | null;
  affectedUrl?: string | null;
  templateId?: string | null;
  checkId?: string | null;
}): string {
  const url = normalizeAffectedUrl(f.affectedUrl);
  const id = (f.templateId || f.checkId || f.cweId || "").toLowerCase();
  const title = (f.title || "")
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
  const cat = (f.category || "").toLowerCase();
  if (id && url) return `${cat}|${id}|${url}`;
  if (f.cweId && url) return `cwe:${f.cweId.toLowerCase()}|${url}`;
  return `${cat}|${title}|${url}`;
}

/** Secondary merge key: CWE + normalized URL (cross-tool even when templateIds differ) */
export function cweUrlKey(f: {
  cweId?: string | null;
  affectedUrl?: string | null;
}): string | null {
  if (!f.cweId) return null;
  const url = normalizeAffectedUrl(f.affectedUrl);
  if (!url) return null;
  return `cwe:${String(f.cweId).toLowerCase()}|${url}`;
}

const CONFIDENCE_RANK: Record<FindingConfidence, number> = {
  confirmed: 3,
  likely: 2,
  heuristic: 1,
};

/** Prefer confirmed evidence when merging duplicates */
export function preferFinding<T extends { confidence?: FindingConfidence | null; evidence?: string | null; severity: string }>(
  a: T,
  b: T
): T {
  const ca = CONFIDENCE_RANK[(a.confidence as FindingConfidence) || "likely"] || 2;
  const cb = CONFIDENCE_RANK[(b.confidence as FindingConfidence) || "likely"] || 2;
  if (cb > ca) return b;
  if (ca > cb) return a;
  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  if ((sevRank[b.severity] || 0) > (sevRank[a.severity] || 0)) return b;
  const ea = (a.evidence || "").length;
  const eb = (b.evidence || "").length;
  return eb > ea ? b : a;
}

export function mergeEvidence(a?: string | null, b?: string | null): string | undefined {
  const parts = [a, b].filter(Boolean) as string[];
  if (!parts.length) return undefined;
  if (parts.length === 1) return parts[0];
  if (parts[0]!.includes(parts[1]!) || parts[1]!.includes(parts[0]!)) return parts[0]!.length >= parts[1]!.length ? parts[0] : parts[1];
  return `${parts[0]}\n---\n${parts[1]}`.slice(0, 8000);
}

/** Coarse scanner family for corroboration counting */
export function scannerFamily(category?: string | null): string {
  const c = (category || "").toLowerCase();
  if (c.includes("nuclei")) return "nuclei";
  if (c.includes("zap")) return "zap";
  if (c.includes("wapiti")) return "wapiti";
  if (c.includes("nikto")) return "nikto";
  if (c.includes("sast") || c.includes("semgrep")) return "sast";
  if (c.includes("sca") || c.includes("dependency")) return "sca";
  if (c.includes("sql")) return "sqli";
  if (c.includes("xss")) return "xss";
  if (c.includes("ssrf")) return "ssrf";
  if (c.includes("graphql")) return "graphql";
  if (c.includes("authorization") || c.includes("auth")) return "authz";
  return c.split(/\s+/)[0] || "other";
}

/**
 * Replace the last numeric / {id}-like path segment with an injection payload.
 * Returns null when the path has no injectable segment.
 */
export function injectPathSegment(path: string, payload: string): string | null {
  const [pathname, query = ""] = path.split("?");
  if (!pathname) return null;
  const replaced = pathname.replace(/\/(?:\d+|\{[^}]+\}|%7B[^%]+%7D)(?=\/|$)/i, `/${encodeURIComponent(payload)}`);
  if (replaced === pathname) return null;
  return query ? `${replaced}?${query}` : replaced;
}

/** Build path-segment injection probe URLs from inventory resource patterns / id paths */
export function pathInjectionTargets(
  extra: ProbeTarget[] | string[] | undefined,
  budget: number
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (p: string) => {
    const key = p.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(p);
  };
  for (const item of extra || []) {
    if (out.length >= budget) break;
    const raw = typeof item === "string" ? item.split("?")[0] : item.path?.split("?")[0];
    if (!raw) continue;
    if (!/\/(?:\d+|\{[^}]+\})(?:\/|$)/.test(raw) && !/\/\{id\}/i.test(raw)) continue;
    const concrete = raw.replace(/\{[^}]+\}/g, "1");
    push(concrete);
  }
  return out.slice(0, budget);
}

/** Merge static paths with OpenAPI/discovery paths (budgeted) */
export function mergeProbePaths(
  staticPaths: string[],
  extra: ProbeTarget[] | string[] | undefined,
  budget: number
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (p: string) => {
    const key = p.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(p);
  };
  for (const p of staticPaths) push(p);
  if (extra) {
    for (const item of extra) {
      if (out.length >= budget) break;
      if (typeof item === "string") {
        if (item.includes("?")) push(item.endsWith("=") || item.includes("=") ? item : `${item}&q=`);
        else if (/graphql|gql/i.test(item)) push(item);
        else if (/\/(?:\d+|\{[^}]+\})(?:\/|$)/.test(item)) {
          push(item.replace(/\{[^}]+\}/g, "1"));
        } else push(`${item}${item.includes("?") ? "&" : "?"}q=`);
      } else if (item.path) {
        const params = item.params?.length ? item.params : ["q", "id", "url", "redirect"];
        const concrete = item.path.replace(/\{[^}]+\}/g, "1");
        if (item.method && item.method !== "GET") {
          push(concrete);
        } else if (/\/(?:\d+|\{[^}]+\})(?:\/|$)/.test(item.path)) {
          push(concrete);
        } else if (item.path.includes("?")) {
          push(item.path);
        } else {
          push(`${concrete}?${params[0]}=`);
        }
      }
    }
  }
  const pathIds = pathInjectionTargets(extra, Math.min(8, Math.max(2, Math.floor(budget / 4))));
  for (const p of pathIds) {
    if (out.length >= budget) break;
    push(p);
  }
  return out.slice(0, budget);
}

/** Absolute URLs for external DAST tools (Nuclei -l / ZAP / Wapiti seeds) */
export function inventoryUrlsForDast(
  targetUrl: string,
  probes: ProbeTarget[] | string[] | undefined,
  budget = 25
): string[] {
  const origin = targetUrl.replace(/\/$/, "");
  const out: string[] = [origin];
  const seen = new Set([origin.toLowerCase()]);
  for (const item of probes || []) {
    if (out.length >= budget) break;
    const raw = typeof item === "string" ? item : item.path;
    if (!raw) continue;
    const path = raw.split("?")[0].replace(/\{[^}]+\}/g, "1");
    if (!path.startsWith("/")) continue;
    const method = typeof item === "string" ? "GET" : (item.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") continue;
    const abs = `${origin}${path}`;
    const key = abs.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(abs);
  }
  return out;
}

/** Extract GraphQL-looking paths from inventory */
export function graphqlPathsFromInventory(extra?: ProbeTarget[] | string[]): string[] {
  const base = ["/graphql", "/api/graphql", "/__graphql", "/gql", "/query", "/v1/graphql"];
  const extras: string[] = [];
  for (const item of extra || []) {
    const p = typeof item === "string" ? item.split("?")[0] : item.path?.split("?")[0];
    if (p && /graphql|\/gql\b|\/query\b/i.test(p)) extras.push(p);
  }
  return Array.from(new Set([...extras, ...base]));
}

/**
 * Parse lightweight injection targets from a GraphQL introspection JSON body.
 * Looks for field(arg: ...) patterns and __schema type/field names.
 */
export function graphqlInjectionTargetsFromIntrospection(body: string): Array<{ field: string; arg: string }> {
  const out: Array<{ field: string; arg: string }> = [];
  const seen = new Set<string>();
  // Match "name":"field","args":[{"name":"id"...}] style fragments loosely
  const fieldArg = /"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"[\s\S]{0,120}?"args"\s*:\s*\[\s*\{\s*"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = fieldArg.exec(body)) !== null && out.length < 12) {
    const key = `${m[1]}:${m[2]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ field: m[1], arg: m[2] });
  }
  // Fallback common shapes
  if (!out.length) {
    out.push({ field: "user", arg: "id" }, { field: "users", arg: "id" }, { field: "search", arg: "q" });
  }
  return out;
}

/** Score weight: heuristic findings count less toward risk */
export function confidenceScoreMultiplier(confidence?: FindingConfidence | null): number {
  if (confidence === "heuristic") return 0.5;
  if (confidence === "confirmed") return 1.15;
  return 1;
}

/** Map Nuclei JSONL row → confidence tier */
export function nucleiConfidenceFromRow(row: Record<string, unknown>): FindingConfidence {
  const matcherStatus = row["matcher-status"];
  const matchType = String(row["type"] || row["matcher-name"] || "").toLowerCase();
  const info = (row.info || {}) as Record<string, unknown>;
  const sev = String(info.severity || row.severity || "").toLowerCase();

  if (matcherStatus === false || matcherStatus === "false") return "heuristic";
  if (sev === "info") return "heuristic";
  if (matchType.includes("http") || matchType.includes("dsl") || matchType.includes("word") || matchType.includes("regex")) {
    if (matcherStatus === true || matcherStatus === "true" || matcherStatus == null) {
      if (row["curl-command"] || row.extractor || row["extracted-results"]) return "confirmed";
      return "likely";
    }
  }
  if (row["curl-command"] && (matcherStatus === true || matcherStatus == null)) return "confirmed";
  return "likely";
}

/** Wapiti module/severity → confidence */
export function wapitiConfidenceFromFinding(input: {
  severity?: string;
  name?: string;
  module?: string;
}): FindingConfidence {
  const sev = (input.severity || "").toLowerCase();
  const name = `${input.name || ""} ${input.module || ""}`.toLowerCase();
  if (sev === "info" || /http.?headers|fingerprint|banner/i.test(name)) return "heuristic";
  if (/sql|xss|ssrf|command|exec|lfi|rfi|ssti/i.test(name) && (sev === "high" || sev === "critical")) return "confirmed";
  if (sev === "high" || sev === "critical") return "likely";
  return "likely";
}

/** SCA confidence from fix availability + severity (+ optional EPSS) */
export function scaConfidenceFromVuln(input: {
  severity: string;
  fixedVersion?: string | null;
  epss?: number | null;
}): FindingConfidence {
  const epss = input.epss;
  if (typeof epss === "number") {
    if (epss >= 0.5) return "confirmed";
    if (epss >= 0.1) return "likely";
    return "heuristic";
  }
  const sev = input.severity.toLowerCase();
  if (!input.fixedVersion && (sev === "low" || sev === "medium")) return "heuristic";
  if (input.fixedVersion && (sev === "critical" || sev === "high")) return "likely";
  if (sev === "critical") return "likely";
  return "heuristic";
}

/** Build focused probe targets from a parent finding for retest */
export function probeTargetsFromFinding(finding: {
  affectedUrl?: string | null;
  templateId?: string | null;
  category?: string | null;
  cweId?: string | null;
}): ProbeTarget[] {
  const out: ProbeTarget[] = [];
  const url = finding.affectedUrl;
  if (url) {
    try {
      const u = new URL(url, "https://normalize.local");
      const path = u.pathname + (u.search || "");
      const params = Array.from(u.searchParams.keys());
      out.push({
        path: path || "/",
        method: "GET",
        params: params.length ? params : ["q", "id", "url"],
        source: "retest",
      });
    } catch {
      out.push({ path: String(url), method: "GET", source: "retest" });
    }
  }
  return out;
}

/** Map finding category / templateId → scanner tool ids for retest */
export function toolsForRetest(finding: {
  category: string;
  title?: string;
  templateId?: string | null;
  cweId?: string | null;
}): string[] {
  const cat = (finding.category || "").toLowerCase();
  const title = (finding.title || "").toLowerCase();
  const tid = (finding.templateId || "").toLowerCase();
  const tools: string[] = [];

  const push = (t: string) => {
    if (!tools.includes(t)) tools.push(t);
  };

  if (cat.includes("nuclei") || tid.includes("cve-") || tid.includes("misconfig")) push("nuclei");
  if (cat.includes("zap") || tid.match(/^\d+$/)) push("zap");
  if (cat.includes("wapiti")) push("wapiti");
  if (cat.includes("sql") || finding.cweId === "CWE-89" || tid.includes("sqli")) push("sqli");
  if (cat.includes("xss") || finding.cweId === "CWE-79" || tid.includes("xss")) push("xss");
  if (cat.includes("ssrf") || finding.cweId === "CWE-918") push("ssrf");
  if (cat.includes("graphql")) push("graphql");
  if (cat.includes("authorization") || cat.includes("auth-roles") || title.includes("privilege") || title.includes("idor") || title.includes("bola")) {
    push("auth-roles");
  }
  if (cat.includes("authentication") || (cat.includes("auth") && !cat.includes("authorization"))) push("auth");
  if (cat.includes("header")) push("headers");
  if (cat.includes("cors")) push("cors");
  if (cat.includes("sast") || cat.includes("semgrep")) push("sast");
  if (cat.includes("sca") || cat.includes("dependency")) push("sca");
  if (tid.startsWith("openapi-post")) {
    push("sqli");
    push("xss");
  }
  if (!tools.length) push("headers");
  return tools.slice(0, 4);
}
