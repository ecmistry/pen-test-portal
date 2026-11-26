import { describe, expect, it } from "vitest";
import { parseOpenApiDocument, extractSchemaPropertyNames } from "./openapiInventory";
import { dedupeFindings, profilePrivilegeRank } from "./scanEngine";
import { mergeProbePaths, normalizeFindingKey, normalizeAffectedUrl, confidenceScoreMultiplier, cweUrlKey, toolsForRetest, injectPathSegment, inventoryUrlsForDast, nucleiConfidenceFromRow, scannerFamily, scaConfidenceFromVuln, wapitiConfidenceFromFinding, probeTargetsFromFinding, graphqlInjectionTargetsFromIntrospection } from "./scanQuality";
import { findingFingerprint } from "./findingFingerprint";

describe("parseOpenApiDocument", () => {
  it("extracts admin and resource endpoints", () => {
    const inv = parseOpenApiDocument({
      paths: {
        "/api/admin/users": { get: { tags: ["admin"], operationId: "listUsers" } },
        "/api/users/{userId}": { get: { tags: ["users"] } },
        "/health": { get: {} },
      },
    });
    expect(inv.endpoints.length).toBe(3);
    expect(inv.adminEndpoints.some((p) => p.includes("admin"))).toBe(true);
    expect(inv.resourcePatterns.some((p) => p.includes("{id}"))).toBe(true);
  });

  it("builds POST probeTargets with inject params", () => {
    const inv = parseOpenApiDocument({
      paths: {
        "/api/search": {
          post: {
            requestBody: {
              content: {
                "application/json": {
                  schema: { type: "object", properties: { q: { type: "string" }, id: { type: "string" } } },
                },
              },
            },
          },
        },
      },
    });
    const posts = (inv.probeTargets || []).filter((p) => p.method === "POST");
    expect(posts.length).toBeGreaterThan(0);
    expect(posts[0].params?.length).toBeGreaterThan(0);
  });
});

describe("profilePrivilegeRank", () => {
  it("prefers explicit privilegeRank", () => {
    expect(profilePrivilegeRank({ name: "admin", type: "bearer", privilegeRank: 1 })).toBe(1);
    expect(profilePrivilegeRank({ name: "admin", type: "bearer" })).toBe(4);
  });
});

describe("dedupeFindings", () => {
  it("keeps higher-confidence duplicate", () => {
    const out = dedupeFindings([
      { title: "Missing HSTS", category: "Headers", severity: "medium" as const, confidence: "heuristic" as const },
      { title: "Missing HSTS", category: "Headers", severity: "medium" as const, confidence: "confirmed" as const, evidence: "detail" },
      { title: "Other", category: "Headers", severity: "low" as const },
    ]);
    expect(out).toHaveLength(2);
    expect(out.find((f) => f.title === "Missing HSTS")?.confidence).toBe("confirmed");
  });
});

describe("scanQuality", () => {
  it("mergeProbePaths budgets and shapes query inject paths", () => {
    const out = mergeProbePaths(["/?id="], [{ path: "/api/items", method: "GET", params: ["q"] }], 5);
    expect(out[0]).toBe("/?id=");
    expect(out.some((p) => p.includes("/api/items"))).toBe(true);
  });

  it("prefers templateId in normalizeFindingKey", () => {
    const a = normalizeFindingKey({ title: "X", category: "Nuclei", affectedUrl: "https://t/a", templateId: "cve-1" });
    const b = normalizeFindingKey({ title: "Y", category: "Nuclei", affectedUrl: "https://t/a", templateId: "cve-1" });
    expect(a).toBe(b);
  });

  it("confidenceScoreMultiplier weights heuristics lower", () => {
    expect(confidenceScoreMultiplier("heuristic")).toBe(0.5);
    expect(confidenceScoreMultiplier("confirmed")).toBeGreaterThan(1);
  });
});

describe("findingFingerprint", () => {
  it("stable for waiver matching", () => {
    expect(findingFingerprint({ title: "Missing HSTS", category: "Headers", cweId: "CWE-1" }))
      .toBe(findingFingerprint({ title: " missing hsts ", category: "headers", cweId: "cwe-1" }));
  });
});

describe("OpenAPI body schema params", () => {
  it("extracts requestBody property names", () => {
    const inv = parseOpenApiDocument({
      components: { schemas: { Search: { type: "object", properties: { query: { type: "string" }, limit: { type: "integer" } } } } },
      paths: {
        "/api/search": {
          post: {
            requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/Search" } } } },
          },
        },
      },
    });
    const post = inv.probeTargets?.find((p) => p.method === "POST");
    expect(post?.params).toEqual(expect.arrayContaining(["query", "limit"]));
  });

  it("includes admin paths from POST ops", () => {
    const inv = parseOpenApiDocument({
      paths: { "/api/admin/reset": { post: { tags: ["admin"] } } },
    });
    expect(inv.adminEndpoints.some((p) => p.includes("admin"))).toBe(true);
  });
});

describe("scanQuality extras", () => {
  it("cweUrlKey + secondary dedupe merges cross-tool", () => {
    expect(cweUrlKey({ cweId: "CWE-89", affectedUrl: "https://t/a/1" })).toContain("cwe-89");
    const out = dedupeFindings([
      { title: "Nuclei SQLi", category: "Nuclei", severity: "critical" as const, cweId: "CWE-89", affectedUrl: "https://t/a/1", templateId: "cve-1", confidence: "likely" as const },
      { title: "SQL injection", category: "SQL Injection", severity: "critical" as const, cweId: "CWE-89", affectedUrl: "https://t/a/2", confidence: "confirmed" as const, evidence: "err" },
    ]);
    expect(out.length).toBe(1);
    expect(out[0].confidence).toBe("confirmed");
  });

  it("injectPathSegment and inventoryUrlsForDast", () => {
    expect(injectPathSegment("/api/users/5", "1'")).toContain(encodeURIComponent("1'"));
    const urls = inventoryUrlsForDast("https://t", [{ path: "/api/items", method: "GET" }, { path: "/api/x", method: "POST" }], 5);
    expect(urls[0]).toBe("https://t");
    expect(urls.some((u) => u.includes("/api/items"))).toBe(true);
    expect(urls.every((u) => !u.endsWith("/api/x"))).toBe(true);
  });

  it("toolsForRetest and nucleiConfidenceFromRow", () => {
    expect(toolsForRetest({ category: "SQL Injection", cweId: "CWE-89" })).toContain("sqli");
    expect(toolsForRetest({ category: "Authorization", title: "BOLA" })).toContain("auth-roles");
    expect(nucleiConfidenceFromRow({ info: { severity: "info" }, "matcher-status": false })).toBe("heuristic");
    expect(nucleiConfidenceFromRow({ info: { severity: "high" }, "matcher-status": true, "curl-command": "curl x", type: "http" })).toBe("confirmed");
  });
});

describe("wave3 quality helpers", () => {
  it("keeps query param names in normalizeAffectedUrl", () => {
    const a = normalizeAffectedUrl("https://t/api?q=1&filter=x");
    const b = normalizeAffectedUrl("https://t/api?filter=y&q=2");
    expect(a).toBe(b);
    expect(a).toContain("filter=");
    expect(a).toContain("q=");
    expect(normalizeAffectedUrl("https://t/api?q=1")).not.toBe(normalizeAffectedUrl("https://t/api?id=1"));
  });

  it("corroboration families and SCA/Wapiti confidence", () => {
    expect(scannerFamily("OWASP ZAP")).toBe("zap");
    expect(scaConfidenceFromVuln({ severity: "critical", fixedVersion: "2.0", epss: 0.7 })).toBe("confirmed");
    expect(scaConfidenceFromVuln({ severity: "low", fixedVersion: null })).toBe("heuristic");
    expect(wapitiConfidenceFromFinding({ severity: "info", name: "HTTP Headers" })).toBe("heuristic");
  });

  it("probeTargetsFromFinding and graphql introspection targets", () => {
    const probes = probeTargetsFromFinding({ affectedUrl: "https://t/search?q=test", category: "XSS" });
    expect(probes[0].path).toContain("/search");
    expect(probes[0].params).toContain("q");
    const targets = graphqlInjectionTargetsFromIntrospection('"name":"user","args":[{"name":"id","type":{}}]');
    expect(targets.some((t) => t.field === "user" && t.arg === "id")).toBe(true);
  });

  it("multi-tool dedupe upgrades confidence", () => {
    const out = dedupeFindings([
      { title: "A", category: "Nuclei", severity: "high" as const, cweId: "CWE-79", affectedUrl: "https://t/x", confidence: "likely" as const },
      { title: "B", category: "XSS", severity: "high" as const, cweId: "CWE-79", affectedUrl: "https://t/x", confidence: "likely" as const, evidence: "reflected" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].confidence).toBe("confirmed");
  });
});
