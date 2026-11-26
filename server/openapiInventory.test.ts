import { describe, expect, it } from "vitest";
import { parseOpenApiDocument } from "./openapiInventory";
import { dedupeFindings, profilePrivilegeRank } from "./scanEngine";

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
});

describe("profilePrivilegeRank", () => {
  it("prefers explicit privilegeRank", () => {
    expect(profilePrivilegeRank({ name: "admin", type: "bearer", privilegeRank: 1 })).toBe(1);
    expect(profilePrivilegeRank({ name: "admin", type: "bearer" })).toBe(4);
  });
});

describe("dedupeFindings", () => {
  it("removes duplicate title/category/severity", () => {
    const out = dedupeFindings([
      { title: "Missing HSTS", category: "Headers", severity: "medium" as const },
      { title: "Missing HSTS", category: "Headers", severity: "medium" as const },
      { title: "Other", category: "Headers", severity: "low" as const },
    ]);
    expect(out).toHaveLength(2);
  });
});
