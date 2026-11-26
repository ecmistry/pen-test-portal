import { normalizeAffectedUrl } from "./scanQuality";

/** Stable fingerprint for waiver matching across scans */
export function findingFingerprint(input: {
  title: string;
  category?: string | null;
  cweId?: string | null;
  affectedUrl?: string | null;
  templateId?: string | null;
  sourceFile?: string | null;
  sourceLine?: number | null;
}): string {
  const title = (input.title || "").trim().toLowerCase();
  const category = (input.category || "").trim().toLowerCase();
  const cwe = (input.cweId || "").trim().toUpperCase();
  const tid = (input.templateId || "").trim().toLowerCase();
  const src = (input.sourceFile || "").trim().toLowerCase().replace(/\\/g, "/");
  const line = input.sourceLine != null ? String(input.sourceLine) : "";
  // Prefer repo coordinates for SAST/Secrets
  if (src && tid) return `${category}::${tid}::${src}:${line}`;
  if (src && cwe) return `${category}::${cwe}::${src}:${line}`;
  if (src) return `${category}::${title}::${src}:${line}`;
  const url = normalizeAffectedUrl(input.affectedUrl);
  if (tid && url) return `${category}::${tid}::${url}`;
  if (cwe && url) return `${category}::${cwe}::${url}`;
  if (url) return `${category}::${title}::${cwe}::${url}`;
  return `${category}::${title}::${cwe}`;
}

/** Legacy title-only fingerprint (for matching older waivers) */
export function legacyFindingFingerprint(input: {
  title: string;
  category?: string | null;
  cweId?: string | null;
}): string {
  const title = (input.title || "").trim().toLowerCase();
  const category = (input.category || "").trim().toLowerCase();
  const cwe = (input.cweId || "").trim().toUpperCase();
  return `${category}::${title}::${cwe}`;
}

/** True if finding matches any active waiver fingerprint (new or legacy) */
export function isWaivedFinding(
  finding: {
    title: string;
    category?: string | null;
    cweId?: string | null;
    affectedUrl?: string | null;
    templateId?: string | null;
    sourceFile?: string | null;
    sourceLine?: number | null;
  },
  waived: Set<string>
): boolean {
  if (waived.has(findingFingerprint(finding))) return true;
  if (waived.has(legacyFindingFingerprint(finding))) return true;
  return false;
}
