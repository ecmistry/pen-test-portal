/**
 * Lightweight discovery crawl: robots.txt, sitemap.xml, HTML links, JS route hints.
 */

export interface DiscoveredRoute {
  path: string;
  source: "robots" | "sitemap" | "html" | "js";
}

function normalizePath(raw: string, baseOrigin: string): string | null {
  try {
    if (!raw || raw.startsWith("mailto:") || raw.startsWith("tel:") || raw.startsWith("javascript:")) return null;
    const u = new URL(raw, baseOrigin);
    if (u.origin !== new URL(baseOrigin).origin) return null;
    let path = u.pathname || "/";
    if (path.length > 200) return null;
    return path;
  } catch {
    return null;
  }
}

export function parseRobotsTxt(text: string, baseOrigin: string): DiscoveredRoute[] {
  const out: DiscoveredRoute[] = [];
  for (const line of text.split("\n")) {
    const m = line.match(/^\s*(?:Allow|Disallow|Sitemap):\s*(\S+)/i);
    if (!m) continue;
    const val = m[1];
    if (/^https?:\/\//i.test(val)) {
      const p = normalizePath(val, baseOrigin);
      if (p) out.push({ path: p, source: "robots" });
    } else if (val.startsWith("/")) {
      out.push({ path: val.split("?")[0], source: "robots" });
    }
  }
  return out;
}

export function parseSitemapXml(xml: string, baseOrigin: string): DiscoveredRoute[] {
  const out: DiscoveredRoute[] = [];
  const re = /<loc>\s*([^<]+)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    const p = normalizePath(m[1].trim(), baseOrigin);
    if (p) out.push({ path: p, source: "sitemap" });
  }
  return out;
}

export function parseHtmlLinks(html: string, baseOrigin: string): DiscoveredRoute[] {
  const out: DiscoveredRoute[] = [];
  const re = /(?:href|src)=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const p = normalizePath(m[1], baseOrigin);
    if (p) out.push({ path: p, source: "html" });
  }
  return out;
}

export function parseJsRouteHints(js: string): DiscoveredRoute[] {
  const out: DiscoveredRoute[] = [];
  const patterns = [
    /["'`](\/(?:api|app|admin|dashboard|auth|login|users|orders|graphql)[A-Za-z0-9_./{}-]*)["'`]/g,
    /path\s*:\s*["'`](\/[A-Za-z0-9_./{}-]*)["'`]/g,
    /route\s*\(\s*["'`](\/[A-Za-z0-9_./{}-]*)["'`]/g,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(js))) {
      const path = m[1].split("?")[0];
      if (path.length > 1 && path.length < 120) out.push({ path, source: "js" });
    }
  }
  return out;
}

export function dedupeRoutes(routes: DiscoveredRoute[], limit = 80): DiscoveredRoute[] {
  const seen = new Set<string>();
  const out: DiscoveredRoute[] = [];
  for (const r of routes) {
    const key = r.path.replace(/\/+$/, "") || "/";
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ...r, path: key });
    if (out.length >= limit) break;
  }
  return out;
}

/** Classify discovered paths into admin-like and resource templates */
export function classifyDiscoveredRoutes(routes: DiscoveredRoute[]): {
  adminEndpoints: string[];
  resourcePatterns: string[];
  allPaths: string[];
} {
  const allPaths = routes.map((r) => r.path);
  const adminEndpoints = allPaths
    .filter((p) => /\/admin\b|\/management\b|\/internal\b|\/superuser\b/i.test(p))
    .slice(0, 40);
  const resourcePatterns = allPaths
    .filter((p) => /\/\d+(\/|$)/.test(p) || /\{[^}]+\}|:id\b/i.test(p))
    .map((p) => p.replace(/\/\d+(?=\/|$)/g, "/{id}").replace(/:([A-Za-z_][\w]*)/g, "{id}"))
    .slice(0, 40);
  return { adminEndpoints, resourcePatterns, allPaths };
}
