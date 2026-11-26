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
  /** Query / path / header / body param names suitable for injection probes */
  injectParams?: string[];
  /** True when operation declares a JSON request body */
  hasJsonBody?: boolean;
}

export interface ApiInventory {
  source: string;
  endpoints: ApiEndpoint[];
  adminEndpoints: string[];
  resourcePatterns: string[];
  /** Probe-ready targets for SQLi/XSS/SSRF/POST injection */
  probeTargets?: Array<{
    path: string;
    method: string;
    params: string[];
    hasJsonBody?: boolean;
    source: "openapi";
  }>;
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

/** Resolve local #/components/schemas/... refs one level deep */
function resolveSchema(root: Record<string, unknown>, schema: unknown, depth = 0): Record<string, unknown> | null {
  if (!schema || typeof schema !== "object" || depth > 4) return null;
  const s = schema as Record<string, unknown>;
  if (typeof s.$ref === "string" && s.$ref.startsWith("#/")) {
    const parts = s.$ref.slice(2).split("/");
    let cur: unknown = root;
    for (const p of parts) {
      if (!cur || typeof cur !== "object") return null;
      cur = (cur as Record<string, unknown>)[p];
    }
    return resolveSchema(root, cur, depth + 1);
  }
  return s;
}

/** Collect property names from a JSON Schema object (incl. allOf / oneOf shallow) */
export function extractSchemaPropertyNames(root: Record<string, unknown>, schema: unknown, depth = 0): string[] {
  const resolved = resolveSchema(root, schema, depth);
  if (!resolved) return [];
  const names: string[] = [];
  const props = resolved.properties;
  if (props && typeof props === "object") {
    for (const key of Object.keys(props as object)) {
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) names.push(key);
    }
  }
  for (const key of ["allOf", "oneOf", "anyOf"] as const) {
    const arr = resolved[key];
    if (Array.isArray(arr)) {
      for (const part of arr.slice(0, 5)) {
        names.push(...extractSchemaPropertyNames(root, part, depth + 1));
      }
    }
  }
  return Array.from(new Set(names)).slice(0, 12);
}

function bodyInjectParams(root: Record<string, unknown>, requestBody: unknown): string[] {
  if (!requestBody || typeof requestBody !== "object") return [];
  const rb = requestBody as Record<string, unknown>;
  const content = rb.content as Record<string, { schema?: unknown }> | undefined;
  if (!content) return [];
  const json =
    content["application/json"] ||
    content["application/x-www-form-urlencoded"] ||
    content["multipart/form-data"];
  if (!json?.schema) return [];
  return extractSchemaPropertyNames(root, json.schema);
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
      const injectParams: string[] = [];
      const params = Array.isArray(operation.parameters) ? (operation.parameters as any[]) : [];
      for (const p of params) {
        const name = p?.name || p?.$ref;
        const inWhere = p?.in;
        if (typeof name === "string" && (inWhere === "query" || inWhere === "path")) {
          injectParams.push(name);
        }
      }
      const rb = operation.requestBody as unknown;
      const hasJsonBody = !!(
        rb &&
        typeof rb === "object" &&
        ((rb as any).content?.["application/json"] ||
          (rb as any).content?.["application/x-www-form-urlencoded"])
      );
      if (hasJsonBody) {
        const bodyParams = bodyInjectParams(root, rb);
        for (const n of bodyParams) {
          if (!injectParams.includes(n)) injectParams.push(n);
        }
      }
      if (hasJsonBody && injectParams.length === 0) {
        injectParams.push("q", "id", "search", "url");
      }
      endpoints.push({
        method: method.toUpperCase(),
        path: rawPath,
        pathTemplate,
        operationId: typeof operation.operationId === "string" ? operation.operationId : undefined,
        tags,
        hasPathId,
        isAdminLikely: isAdminPath(rawPath, tags),
        injectParams: injectParams.slice(0, 8),
        hasJsonBody,
      });
    }
  }

  // Include write methods for admin surfaces (not GET-only)
  // Admin paths from any method (GET-only previously missed POST /admin/*)
  const adminEndpoints = Array.from(
    new Set(
      endpoints
        .filter((e) => e.isAdminLikely)
        .map((e) => e.path.replace(/\{[^}]+\}/g, "1"))
    )
  ).slice(0, 50);

  const resourcePatterns = Array.from(
    new Set(
      endpoints
        .filter((e) => e.hasPathId && ["GET", "PUT", "PATCH", "DELETE"].includes(e.method))
        .map((e) => e.pathTemplate)
    )
  ).slice(0, 40);

  const probeTargets = endpoints
    .filter((e) => ["GET", "POST", "PUT", "PATCH"].includes(e.method))
    .slice(0, 80)
    .map((e) => ({
      path: e.path.replace(/\{[^}]+\}/g, "1"),
      method: e.method,
      params: e.injectParams?.length ? e.injectParams : ["q", "id", "url", "redirect"],
      hasJsonBody: e.hasJsonBody,
      source: "openapi" as const,
    }));

  return { source, endpoints, adminEndpoints, resourcePatterns, probeTargets };
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
