/**
 * Minimal CycloneDX 1.5 SBOM builder from OSV/SCA-style dependency findings + manifest hints.
 */
export type SbomComponent = {
  name: string;
  version?: string;
  purl?: string;
  type?: string;
};

export function buildCycloneDxSbom(opts: {
  targetName: string;
  targetUrl: string;
  scanId: number;
  components: SbomComponent[];
  vulnerabilities?: Array<{ id: string; description?: string; severity?: string; affects?: string[] }>;
}): object {
  const now = new Date().toISOString();
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:ghoststrike-${opts.scanId}-${Date.now()}`,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [{ vendor: "Ghoststrike", name: "pen-test-portal", version: "1.0.0" }],
      component: {
        type: "application",
        name: opts.targetName,
        version: "0.0.0",
        description: opts.targetUrl,
      },
    },
    components: opts.components.map((c) => ({
      type: c.type || "library",
      name: c.name,
      version: c.version || "unknown",
      purl: c.purl,
    })),
    vulnerabilities: (opts.vulnerabilities || []).map((v) => ({
      id: v.id,
      description: v.description,
      ratings: v.severity ? [{ severity: v.severity }] : undefined,
      affects: (v.affects || []).map((ref) => ({ ref })),
    })),
  };
}

/** Prefer structured SCA vulns; fall back to parsing finding titles / evidence */
export function componentsFromScaVulns(
  vulns: Array<{ package: string; installedVersion: string; cve: string; severity?: string; summary?: string }>
): { components: SbomComponent[]; vulnerabilities: Array<{ id: string; description?: string; severity?: string; affects?: string[] }> } {
  const components: SbomComponent[] = [];
  const vulnerabilities: Array<{ id: string; description?: string; severity?: string; affects?: string[] }> = [];
  const seen = new Set<string>();
  for (const v of vulns) {
    const key = `${v.package}@${v.installedVersion}`;
    if (!seen.has(key)) {
      seen.add(key);
      components.push({ name: v.package, version: v.installedVersion });
    }
    if (v.cve) {
      vulnerabilities.push({
        id: v.cve.toUpperCase(),
        description: v.summary || `${v.package} ${v.installedVersion}`,
        severity: v.severity,
        affects: [v.package],
      });
    }
  }
  return { components, vulnerabilities };
}

/** Parse package names from common finding titles / evidence lines */
export function componentsFromScaFindings(
  findings: Array<{ title: string; evidence?: string | null; category: string; severity?: string }>
): { components: SbomComponent[]; vulnerabilities: Array<{ id: string; description?: string; severity?: string; affects?: string[] }> } {
  const components: SbomComponent[] = [];
  const vulnerabilities: Array<{ id: string; description?: string; severity?: string; affects?: string[] }> = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (!/sca|osv|dependenc|package|cve|npm|pip|cargo/i.test(f.category + f.title)) continue;
    const pkgLine = f.evidence?.match(/Package:\s*([^\n]+)/i);
    const verLine = f.evidence?.match(/Installed:\s*([^\n]+)/i);
    const m =
      f.title.match(/Vulnerable Dependency:\s*([A-Za-z0-9_@/.-]+)\s+([\w.-]+)/i) ||
      f.title.match(/([A-Za-z0-9_@/.-]+)@([\w.-]+)/) ||
      f.evidence?.match(/package[:\s]+([A-Za-z0-9_@/.-]+)(?:@([\w.-]+))?/i);
    const name = (pkgLine?.[1] || m?.[1] || f.title.slice(0, 80)).trim();
    const version = (verLine?.[1] || m?.[2] || undefined)?.trim();
    const key = `${name}@${version || "?"}`;
    if (!seen.has(key)) {
      seen.add(key);
      components.push({ name, version });
    }
    const cve = f.title.match(/CVE-\d{4}-\d+/i)?.[0] || f.evidence?.match(/CVE-\d{4}-\d+/i)?.[0];
    if (cve) {
      vulnerabilities.push({
        id: cve.toUpperCase(),
        description: f.title,
        severity: f.severity,
        affects: [name],
      });
    }
  }
  return { components, vulnerabilities };
}
