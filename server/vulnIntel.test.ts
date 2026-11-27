import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "fs/promises";
import os from "os";
import path from "path";
import {
  buildThreatIntelForTexts,
  clearVulnIntelMemoryCache,
  extractCveIds,
  parseEpssCsv,
  parseKevCatalog,
  parseNvdCveResponse,
} from "./vulnIntel";

describe("vulnIntel parsers", () => {
  it("extractCveIds finds unique CVE IDs", () => {
    expect(extractCveIds("CVE-2021-44228 in log4j", "also CVE-2021-44228 and cve-2014-0160")).toEqual([
      "CVE-2021-44228",
      "CVE-2014-0160",
    ]);
  });

  it("parseKevCatalog indexes by CVE", () => {
    const map = parseKevCatalog({
      vulnerabilities: [
        {
          cveID: "CVE-2021-44228",
          vendorProject: "Apache",
          product: "Log4j",
          dateAdded: "2021-12-10",
          dueDate: "2021-12-24",
          requiredAction: "Apply updates",
          knownRansomwareCampaignUse: "Known",
          shortDescription: "RCE",
        },
      ],
    });
    expect(map["CVE-2021-44228"]?.vendorProject).toBe("Apache");
    expect(map["CVE-2021-44228"]?.dueDate).toBe("2021-12-24");
  });

  it("parseEpssCsv builds score map", () => {
    const csv = `# comment\ncve,epss,percentile\nCVE-2021-44228,0.97543,0.99999\nCVE-2014-0160,0.12345,0.90000\n`;
    const map = parseEpssCsv(csv);
    expect(map["CVE-2021-44228"]?.epss).toBeCloseTo(0.97543);
    expect(map["CVE-2014-0160"]?.percentile).toBeCloseTo(0.9);
  });

  it("parseNvdCveResponse extracts CVSS 3.1", () => {
    const parsed = parseNvdCveResponse(
      {
        vulnerabilities: [
          {
            cve: {
              descriptions: [{ lang: "en", value: "Remote code execution" }],
              metrics: {
                cvssMetricV31: [
                  {
                    cvssData: {
                      version: "3.1",
                      baseScore: 10,
                      vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    },
                  },
                ],
              },
              references: [{ url: "https://example.com/advisory" }],
              published: "2021-12-10T00:00:00.000",
            },
          },
        ],
      },
      "CVE-2021-44228"
    );
    expect(parsed?.cvssScore).toBe(10);
    expect(parsed?.description).toContain("Remote code");
    expect(parsed?.references?.[0]).toContain("example.com");
  });
});

describe("buildThreatIntelForTexts", () => {
  const prevCwd = process.cwd();
  let tmp: string;

  afterEach(async () => {
    clearVulnIntelMemoryCache();
    process.chdir(prevCwd);
    if (tmp) await fs.rm(tmp, { recursive: true, force: true });
  });

  it("applies KEV + EPSS from local cache without NVD fetch", async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "vuln-intel-"));
    process.chdir(tmp);
    await fs.mkdir(path.join(tmp, "data", "vuln-intel"), { recursive: true });
    await fs.writeFile(
      path.join(tmp, "data", "vuln-intel", "kev.json"),
      JSON.stringify({
        "CVE-2021-44228": {
          cveId: "CVE-2021-44228",
          dueDate: "2021-12-24",
          requiredAction: "Patch now",
          knownRansomwareCampaignUse: "Known",
        },
      })
    );
    await fs.writeFile(
      path.join(tmp, "data", "vuln-intel", "epss.json"),
      JSON.stringify({ "CVE-2021-44228": { epss: 0.97, percentile: 0.99 } })
    );
    await fs.writeFile(path.join(tmp, "data", "vuln-intel", "nvd-cache.json"), JSON.stringify({}));

    const intel = await buildThreatIntelForTexts(["Nuclei hit CVE-2021-44228"], { fetchMissingNvd: false });
    expect(intel).not.toBeNull();
    expect(intel!.inKev).toBe(true);
    expect(intel!.bumpPriorityToP1).toBe(true);
    expect(intel!.epss).toBeCloseTo(0.97);
    expect(intel!.confidenceHint).toBe("confirmed");
    expect(intel!.evidenceExtra).toContain("CISA KEV");
    expect(intel!.evidenceExtra).toContain("EPSS");
    expect(intel!.exploitDbUrls[0]).toContain("exploit-db.com");
  });
});
