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

/** Normalize URL for correlation (drop fragment, sort query keys lightly) */
export function normalizeAffectedUrl(url?: string | null): string {
  if (!url) return "";
  try {
    const u = new URL(url, "https://normalize.local");
    u.hash = "";
    // Collapse numeric path segments for IDOR-ish correlation
    const path = u.pathname.replace(/\/\d+(?=\/|$)/g, "/{id}");
    return `${u.origin}${path}`.toLowerCase();
  } catch {
    return String(url).toLowerCase().split("?")[0];
  }
}

/** Stable correlation key across tools */
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
        // Convert bare paths to injectable query forms when needed
        if (item.includes("?")) push(item.endsWith("=") || item.includes("=") ? item : `${item}&q=`);
        else if (/graphql|gql/i.test(item)) push(item);
        else push(`${item}${item.includes("?") ? "&" : "?"}q=`);
      } else if (item.path) {
        const params = item.params?.length ? item.params : ["q", "id", "url", "redirect"];
        if (item.method && item.method !== "GET") {
          push(item.path); // POST handled separately
        } else if (item.path.includes("?")) {
          push(item.path);
        } else {
          push(`${item.path}?${params[0]}=`);
        }
      }
    }
  }
  return out.slice(0, budget);
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
