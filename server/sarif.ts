/**
 * SARIF 2.1.0 export for GitHub Code Scanning / Azure DevOps / etc.
 */
import type { ReportData } from "./reportGenerator";

const SEVERITY_TO_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SEVERITY_TO_SECURITY: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "none",
};

export function generateSarifReport(data: ReportData): object {
  const { scan, target, findings, generatedAt } = data;
  const rulesMap = new Map<string, { id: string; name: string; fullDescription: string; helpUri?: string }>();

  for (const f of findings) {
    const id = f.cweId || `GS-${f.category.replace(/\s+/g, "-")}-${f.id}`;
    if (!rulesMap.has(id)) {
      rulesMap.set(id, {
        id,
        name: f.title,
        fullDescription: f.description || f.title,
        helpUri: f.cweId ? `https://cwe.mitre.org/data/definitions/${f.cweId.replace(/^CWE-/i, "")}.html` : undefined,
      });
    }
  }

  const results = findings
    .filter((f) => f.status !== "false_positive" && f.status !== "resolved")
    .map((f) => {
      const ruleId = f.cweId || `GS-${f.category.replace(/\s+/g, "-")}-${f.id}`;
      const uri = (f as any).affectedUrl || (f as any).sourceFile || target.url;
      const result: Record<string, unknown> = {
        ruleId,
        level: SEVERITY_TO_LEVEL[f.severity] || "warning",
        message: { text: f.title + (f.description ? `\n\n${f.description}` : "") },
        properties: {
          security_severity: SEVERITY_TO_SECURITY[f.severity] || "medium",
          category: f.category,
          status: f.status,
          cwe: f.cweId || undefined,
          owasp: f.owaspCategory || undefined,
          tags: ["security", f.category, f.severity].filter(Boolean),
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: String(uri) },
              ...((f as any).sourceLine
                ? { region: { startLine: (f as any).sourceLine } }
                : {}),
            },
          },
        ],
      };
      if (f.evidence) {
        result.partialFingerprints = {
          primaryLocationLineHash: String(f.id),
        };
      }
      return result;
    });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Ghoststrike",
            informationUri: "https://ghoststrike.tech",
            version: "1.0.0",
            rules: Array.from(rulesMap.values()).map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.name },
              fullDescription: { text: r.fullDescription },
              helpUri: r.helpUri,
              properties: { tags: ["security"] },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: scan.status === "completed",
            endTimeUtc: (scan.completedAt || generatedAt).toISOString?.() ?? new Date(generatedAt).toISOString(),
            workingDirectory: { uri: target.url },
          },
        ],
        results,
        properties: {
          scanId: scan.id,
          targetId: target.id,
          securityScore: scan.securityScore,
          riskLevel: scan.riskLevel,
        },
      },
    ],
  };
}
