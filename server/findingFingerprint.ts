/** Stable fingerprint for waiver matching across scans */
export function findingFingerprint(input: {
  title: string;
  category?: string | null;
  cweId?: string | null;
}): string {
  const title = (input.title || "").trim().toLowerCase();
  const category = (input.category || "").trim().toLowerCase();
  const cwe = (input.cweId || "").trim().toUpperCase();
  return `${category}::${title}::${cwe}`;
}
