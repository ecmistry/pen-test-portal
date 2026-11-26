import { describe, expect, it } from "vitest";
import { parseOpenApiDocument } from "./openapiInventory";
import { dedupeFindings, profilePrivilegeRank } from "./scanEngine";
import { mergeProbePaths, normalizeFindingKey, confidenceScoreMultiplier } from "./scanQuality";
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
