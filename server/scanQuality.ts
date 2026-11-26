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
  source?: "static" | "openapi" | "discovery";
};

/** Normalize URL for correlation (drop fragment, collapse numeric IDs) */
export function normalizeAffectedUrl(url?: string | null): string {
  if (!url) return "";
  try {
    const u = new URL(url, "https://normalize.local");
    u.hash = "";
    const path = u.pathname.replace(/\/\d+(?=\/|$)/g, "/{id}");
    return `${u.origin}${path}`.toLowerCase();
  } catch {
    return String(url).toLowerCase().split("?")[0];
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
    // Only paths that look like resource IDs
    if (!/\/(?:\d+|\{[^}]+\})(?:\/|$)/.test(raw) && !/\/\{id\}/i.test(raw)) continue;
    // Marker path used as baseline prefix (payload appended by caller via injectPathSegment)
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
          // Path-id routes: keep concrete path for segment injection callers
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
  // Reserve room for path-segment probes from inventory
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
    // Skip obvious write-only noise for GET-oriented DAST seeds
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
      // Extractors / curl present → stronger signal
      if (row["curl-command"] || row.extractor || row["extracted-results"]) return "confirmed";
      return "likely";
    }
  }
  if (row["curl-command"] && (matcherStatus === true || matcherStatus == null)) return "confirmed";
  return "likely";
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
  if (tid.startsWith("openapi-post")) {
    push("sqli");
    push("xss");
  }
  if (!tools.length) push("headers");
  return tools.slice(0, 4);
}
