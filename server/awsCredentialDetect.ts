/**
 * AWS credential exposure detection helpers.
 *
 * Inspired by the honeytoken threat model in canaries.md: find exposed AWS keys
 * before an attacker does. Ghoststrike must NEVER call AWS APIs with discovered
 * keys to "validate" them — that would burn real keys and trip canaries.
 */

export const AWS_ACCESS_KEY_ID_RE = /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g;
export const AWS_SECRET_ACCESS_KEY_RE =
  /(?:aws_secret_access_key\s*=\s*|["']?(?:secretAccessKey|aws_secret_access_key|secret_key)["']?\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})/gi;
export const AWS_CREDENTIALS_INI_RE =
  /(?:^|\n)\s*aws_access_key_id\s*=\s*((?:AKIA|ASIA)[0-9A-Z]{16})\s*(?:\n|$)/i;
export const AWS_NAMED_PROFILE_RE = /(?:^|\n)\s*\[([^\]]+)\]\s*\n(?:[^\[]*\n)*?\s*aws_access_key_id\s*=\s*((?:AKIA|ASIA)[0-9A-Z]{16})/gi;

export interface AwsKeyHit {
  accessKeyId: string;
  isTemporary: boolean;
  isHoneytoken: boolean;
  profileName?: string;
  maskedAccessKeyId: string;
}

export function maskAwsAccessKeyId(keyId: string): string {
  if (keyId.length < 8) return "****";
  return `${keyId.slice(0, 4)}****${keyId.slice(-4)}`;
}

/** Comma-separated Access Key IDs or prefixes from CANARY_AWS_KEY_PREFIXES */
export function getCanaryAwsKeyPrefixes(envValue = process.env.CANARY_AWS_KEY_PREFIXES): string[] {
  if (!envValue?.trim()) return [];
  return envValue
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter((s) => s.length >= 4);
}

export function isConfiguredCanaryKey(accessKeyId: string, prefixes = getCanaryAwsKeyPrefixes()): boolean {
  const id = accessKeyId.toUpperCase();
  return prefixes.some((p) => id === p || id.startsWith(p));
}

export function looksLikeAwsCredentialsFile(body: string): boolean {
  const b = body.substring(0, 4000);
  if (/^\s*</.test(b.trim())) return false; // HTML
  return (
    AWS_CREDENTIALS_INI_RE.test(b) ||
    (/\[[^\]]+\]/.test(b) && /aws_access_key_id\s*=/i.test(b)) ||
    (/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/.test(b) && /aws_secret_access_key\s*=/i.test(b))
  );
}

export function extractAwsKeyHits(body: string, canaryPrefixes = getCanaryAwsKeyPrefixes()): AwsKeyHit[] {
  const hits = new Map<string, AwsKeyHit>();
  const text = body.substring(0, 50_000);

  // Named profiles first (capture profile context)
  AWS_NAMED_PROFILE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = AWS_NAMED_PROFILE_RE.exec(text)) !== null) {
    const profileName = m[1]?.trim();
    const accessKeyId = m[2].toUpperCase();
    hits.set(accessKeyId, {
      accessKeyId,
      isTemporary: accessKeyId.startsWith("ASIA"),
      isHoneytoken: isConfiguredCanaryKey(accessKeyId, canaryPrefixes),
      profileName,
      maskedAccessKeyId: maskAwsAccessKeyId(accessKeyId),
    });
  }

  AWS_ACCESS_KEY_ID_RE.lastIndex = 0;
  while ((m = AWS_ACCESS_KEY_ID_RE.exec(text)) !== null) {
    const accessKeyId = m[1].toUpperCase();
    if (hits.has(accessKeyId)) continue;
    hits.set(accessKeyId, {
      accessKeyId,
      isTemporary: accessKeyId.startsWith("ASIA"),
      isHoneytoken: isConfiguredCanaryKey(accessKeyId, canaryPrefixes),
      maskedAccessKeyId: maskAwsAccessKeyId(accessKeyId),
    });
  }

  return Array.from(hits.values());
}

export function awsCredentialsRemediation(isHoneytoken: boolean): string {
  if (isHoneytoken) {
    return (
      "This Access Key ID matches a configured honeytoken/canary prefix. Treat the host as compromised: " +
      "isolate the server, preserve logs, rotate real secrets the host could reach, and follow the canary incident runbook. " +
      "Do not dismiss as a false positive — exposure means the decoy left the box."
    );
  }
  return (
    "Immediately rotate/revoke the exposed AWS access key in IAM. Remove credentials from web-accessible paths. " +
    "Never place canary or real keys in the [default] profile or AWS_* environment variables on servers that use instance roles " +
    "(that overrides the instance role and breaks workloads). Prefer a named profile only for intentional tooling, " +
    "and keep real workload credentials on the instance role / secrets manager."
  );
}

/** Shared finding fields for AWS key exposure (never includes full secret material). */
export function describeAwsKeyExposure(hit: AwsKeyHit): {
  title: string;
  description: string;
  evidenceExtra: string;
  severity: "critical" | "high";
} {
  const kind = hit.isTemporary ? "temporary (ASIA)" : "long-term (AKIA)";
  const honeytoken = hit.isHoneytoken ? " [honeytoken=true]" : "";
  const profile = hit.profileName ? ` profile=[${hit.profileName}]` : "";
  return {
    title: hit.profileName
      ? `Exposed AWS credentials profile [${hit.profileName}]`
      : `Exposed AWS access key ID (${hit.maskedAccessKeyId})`,
    description:
      `An AWS ${kind} access key ID was found in a publicly reachable response${profile}.${honeytoken} ` +
      `Attackers can attempt to use stolen keys for cloud API access. ` +
      `Ghoststrike does not validate keys against AWS APIs (to avoid burning keys or tripping canaries).`,
    evidenceExtra: [
      `AccessKeyId (masked): ${hit.maskedAccessKeyId}`,
      `Key type: ${kind}`,
      hit.profileName ? `Profile: [${hit.profileName}]` : null,
      hit.isHoneytoken ? "honeytoken=true (matches CANARY_AWS_KEY_PREFIXES)" : null,
    ]
      .filter(Boolean)
      .join("\n"),
    severity: hit.isHoneytoken || hit.profileName ? "critical" : "high",
  };
}
