import { describe, expect, it } from "vitest";
import { buildCycloneDxSbom, componentsFromScaFindings } from "./sbom";

describe("sbom", () => {
  it("builds CycloneDX document", () => {
    const bom = buildCycloneDxSbom({
      targetName: "app",
      targetUrl: "https://app.example.com",
      scanId: 7,
      components: [{ name: "lodash", version: "4.17.20" }],
      vulnerabilities: [{ id: "CVE-2021-23337", affects: ["lodash"] }],
    }) as any;
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.components[0].name).toBe("lodash");
    expect(bom.vulnerabilities[0].id).toBe("CVE-2021-23337");
  });

  it("extracts components from SCA findings", () => {
    const { components, vulnerabilities } = componentsFromScaFindings([
      {
        title: "CVE-2021-23337 in lodash@4.17.20",
        category: "SCA",
        evidence: "package: lodash@4.17.20",
      },
    ]);
    expect(components.length).toBeGreaterThan(0);
    expect(vulnerabilities.some((v) => v.id.includes("CVE-2021"))).toBe(true);
  });
});
