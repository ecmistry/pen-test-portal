/**
 * Parse OpenAPI/Swagger documents into an endpoint inventory for authz/IDOR testing.
 */

export interface ApiEndpoint {
  method: string;
  path: string;
  operationId?: string;
  tags?: string[];
  /** Path with `{id}` style params preserved */
  pathTemplate: string;
  hasPathId: boolean;
  isAdminLikely: boolean;
}

export interface ApiInventory {
  source: string;
  endpoints: ApiEndpoint[];
  adminEndpoints: string[];
  resourcePatterns: string[];
}

function isAdminPath(path: string, tags?: string[]): boolean {
  const lower = path.toLowerCase();
  if (/\/admin\b|\/management\b|\/internal\b|\/superuser\b/.test(lower)) return true;
  if (tags?.some((t) => /admin|management|internal/i.test(t))) return true;
  return false;
}

function normalizePathTemplate(path: string): string {
  return path
    .replace(/\{[^}]+\}/g, "{id}")
    .replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{id}");
}

export function parseOpenApiDocument(doc: unknown, source = "openapi"): ApiInventory {
  const endpoints: ApiEndpoint[] = [];
  if (!doc || typeof doc !== "object") {
    return { source, endpoints, adminEndpoints: [], resourcePatterns: [] };
  }

  const root = doc as Record<string, unknown>;
  const paths = (root.paths ?? {}) as Record<string, Record<string, unknown>>;

  for (const [rawPath, methods] of Object.entries(paths)) {
    if (!methods || typeof methods !== "object") continue;
    for (const [method, op] of Object.entries(methods)) {
      if (!["get", "post", "put", "patch", "delete", "head", "options"].includes(method.toLowerCase())) continue;
      const operation = (op ?? {}) as Record<string, unknown>;
      const tags = Array.isArray(operation.tags) ? (operation.tags as string[]) : undefined;
      const pathTemplate = normalizePathTemplate(rawPath);
      const hasPathId = /\{id\}/.test(pathTemplate) || /\{[^}]+\}/.test(rawPath);
      endpoints.push({
        method: method.toUpperCase(),
        path: rawPath,
        pathTemplate,
        operationId: typeof operation.operationId === "string" ? operation.operationId : undefined,
        tags,
        hasPathId,
        isAdminLikely: isAdminPath(rawPath, tags),
      });
    }
  }

  const adminEndpoints = Array.from(
    new Set(
      endpoints
        .filter((e) => e.isAdminLikely && e.method === "GET")
        .map((e) => e.path.replace(/\{[^}]+\}/g, "1"))
    )
  ).slice(0, 40);

  const resourcePatterns = Array.from(
    new Set(endpoints.filter((e) => e.hasPathId && e.method === "GET").map((e) => e.pathTemplate))
  ).slice(0, 40);

  return { source, endpoints, adminEndpoints, resourcePatterns };
}

export async function fetchOpenApiInventory(openapiUrl: string): Promise<ApiInventory | null> {
  try {
    const res = await fetch(openapiUrl, {
      headers: { Accept: "application/json", "User-Agent": "PenTestPortal/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return null;
    const doc = await res.json();
    return parseOpenApiDocument(doc, openapiUrl);
  } catch {
    return null;
  }
}
