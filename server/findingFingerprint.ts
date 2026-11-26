import { normalizeAffectedUrl } from "./scanQuality";

/** Stable fingerprint for waiver matching across scans */
export function findingFingerprint(input: {
  title: string;
  category?: string | null;
  cweId?: string | null;
  affectedUrl?: string | null;
  templateId?: string | null;
}): string {
  const title = (input.title || "").trim().toLowerCase();
  const category = (input.category || "").trim().toLowerCase();
  const cwe = (input.cweId || "").trim().toUpperCase();
  const url = normalizeAffectedUrl(input.affectedUrl);
  const tid = (input.templateId || "").trim().toLowerCase();
  // Prefer template+url when available; else cwe+url; else legacy title key
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
  },
  waived: Set<string>
): boolean {
  if (waived.has(findingFingerprint(finding))) return true;
  if (waived.has(legacyFindingFingerprint(finding))) return true;
  return false;
}
