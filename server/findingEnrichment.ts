/**
 * Finding Enrichment — derives CVSSv3.1, business impact, remediation metadata,
 * MITRE ATT&CK mapping, and ISO 27001 control references from a finding's
 * category, severity, and CWE ID.
 *
 * All mappings are rule-based lookup tables. The enrichment function is called
 * once per finding at scan time; results are stored alongside the finding in the DB.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CvssData {
  version: "3.1";
  vectorString: string;
  baseScore: number;
  baseSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
}

export type ImpactLevel = "Critical" | "High" | "Medium" | "Low" | "None";

export interface BusinessImpact {
  financial: ImpactLevel;
  operational: ImpactLevel;
  reputational: ImpactLevel;
  legal: ImpactLevel;
  rationale: string;
}

export type RemediationComplexity = "Low" | "Medium" | "High";
export type RemediationPriority = "P1" | "P2" | "P3" | "P4";

export interface AttackTechnique {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
}

export interface EnrichedFields {
  cvssVector: string | null;
  cvssScore: number | null;
  businessImpact: BusinessImpact | null;
  remediationComplexity: RemediationComplexity | null;
  remediationPriority: RemediationPriority | null;
  attackTechniques: AttackTechnique[] | null;
  iso27001Controls: string[] | null;
}

// ─── CVSSv3.1 ─────────────────────────────────────────────────────────────────
// Pre-computed vectors for common finding types. Keyed by normalised category.
// Vectors follow: AV:N/AC:L|H/PR:N|L/UI:N|R/S:U|C/C:H|L|N/I:H|L|N/A:H|L|N

interface CvssEntry { vector: string; score: number; }

const CVSS_BY_CATEGORY: Record<string, CvssEntry> = {
  "sql injection":         { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
  "cross-site scripting":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score: 6.1 },
  "xss":                   { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score: 6.1 },
  "authentication":        { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 9.1 },
  "cors":                  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", score: 6.5 },
  "path traversal":        { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5 },
  "security misconfiguration": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  "information disclosure": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  "tls":                   { vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 5.9 },
  "business logic":        { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", score: 6.5 },
  "graphql":               { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  "authorization":         { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", score: 8.1 },
  "sca":                   { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
  "ssrf":                  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", score: 9.1 },
};

const CVSS_BY_CWE: Record<string, CvssEntry> = {
  "CWE-89":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
  "CWE-79":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score: 6.1 },
  "CWE-22":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5 },
  "CWE-307": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 9.1 },
  "CWE-203": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  "CWE-693": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", score: 5.3 },
  "CWE-311": { vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 5.9 },
  "CWE-200": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  "CWE-538": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5 },
  "CWE-942": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", score: 6.5 },
  "CWE-1021": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", score: 4.3 },
  "CWE-326":  { vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 5.9 },
  "CWE-295":  { vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 5.9 },
  "CWE-319":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5 },
  "CWE-215":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  "CWE-352":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", score: 6.5 },
  "CWE-915":  { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", score: 6.5 },
  "CWE-209":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  "CWE-770":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", score: 7.5 },
  "CWE-400":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", score: 5.3 },
  "CWE-269":  { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", score: 8.1 },
  "CWE-284":  { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", score: 7.1 },
  "CWE-639":  { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", score: 6.5 },
  "CWE-502":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
  "CWE-918":  { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", score: 9.1 },
  "CWE-1104": { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
};

const CVSS_SEVERITY_FALLBACK: Record<string, CvssEntry> = {
  critical: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
  high:     { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", score: 8.2 },
  medium:   { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", score: 6.5 },
  low:      { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", score: 3.1 },
  info:     { vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", score: 0.0 },
};

function cvssSeverityLabel(score: number): CvssData["baseSeverity"] {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0.0)  return "LOW";
  return "NONE";
}

function deriveCvss(category: string, severity: string, cweId?: string | null): CvssData | null {
  if (severity === "info" || category === "Tool Availability" || category === "Connectivity") return null;

  const entry =
    (cweId ? CVSS_BY_CWE[cweId] : null) ??
    CVSS_BY_CATEGORY[category.toLowerCase()] ??
    CVSS_SEVERITY_FALLBACK[severity] ??
    null;

  if (!entry) return null;
  return { version: "3.1", vectorString: entry.vector, baseScore: entry.score, baseSeverity: cvssSeverityLabel(entry.score) };
}

// ─── Business Impact ──────────────────────────────────────────────────────────

interface ImpactProfile {
  financial: ImpactLevel;
  operational: ImpactLevel;
  reputational: ImpactLevel;
  legal: ImpactLevel;
  rationale: string;
}

const IMPACT_BY_CATEGORY: Record<string, ImpactProfile> = {
  "sql injection": {
    financial: "High", operational: "High", reputational: "High", legal: "High",
    rationale: "SQL injection may allow full database compromise, data exfiltration, and regulatory breach notification obligations (GDPR, PCI DSS).",
  },
  "cross-site scripting": {
    financial: "Medium", operational: "Medium", reputational: "High", legal: "Medium",
    rationale: "XSS can lead to session hijacking, credential theft, and defacement — damaging user trust and triggering breach obligations if PII is exposed.",
  },
  "xss": {
    financial: "Medium", operational: "Medium", reputational: "High", legal: "Medium",
    rationale: "XSS can lead to session hijacking, credential theft, and defacement — damaging user trust and triggering breach obligations if PII is exposed.",
  },
  "authentication": {
    financial: "High", operational: "High", reputational: "Medium", legal: "Medium",
    rationale: "Weak authentication may allow account takeover, unauthorised data access, and breach of access control requirements.",
  },
  "cors": {
    financial: "Medium", operational: "Low", reputational: "Medium", legal: "Medium",
    rationale: "CORS misconfiguration may permit cross-origin credential theft or data exfiltration from authenticated sessions.",
  },
  "path traversal": {
    financial: "High", operational: "High", reputational: "Medium", legal: "High",
    rationale: "Path traversal may expose server configuration, credentials, or source code — enabling further compromise and regulatory exposure.",
  },
  "security headers": {
    financial: "Low", operational: "Low", reputational: "Low", legal: "Low",
    rationale: "Missing security headers increase susceptibility to client-side attacks but do not directly expose data.",
  },
  "security misconfiguration": {
    financial: "Low", operational: "Medium", reputational: "Low", legal: "Low",
    rationale: "Misconfigured services may expose unintended functionality or information, facilitating further attacks.",
  },
  "information disclosure": {
    financial: "Medium", operational: "Low", reputational: "Medium", legal: "Medium",
    rationale: "Exposed configuration or credentials may enable further attacks and may trigger breach obligations if sensitive data is involved.",
  },
  "nikto": {
    financial: "Medium", operational: "Medium", reputational: "Low", legal: "Low",
    rationale: "Server misconfigurations or outdated components may be exploitable. Impact depends on the specific finding.",
  },
  "nuclei": {
    financial: "Medium", operational: "Medium", reputational: "Medium", legal: "Medium",
    rationale: "Template-matched CVEs or misconfigurations may be directly exploitable. Impact depends on the specific vulnerability.",
  },
  "owasp zap": {
    financial: "Medium", operational: "Medium", reputational: "Low", legal: "Low",
    rationale: "DAST-identified issues may represent exploitable vulnerabilities. Impact depends on the specific finding.",
  },
  "tls": {
    financial: "Medium", operational: "Medium", reputational: "High", legal: "High",
    rationale: "Weak TLS may allow traffic interception, exposing credentials and sensitive data. May violate PCI DSS, GDPR, and similar regulations requiring encryption in transit.",
  },
  "business logic": {
    financial: "Medium", operational: "Medium", reputational: "Medium", legal: "Medium",
    rationale: "Business logic flaws may allow privilege escalation, workflow bypass, or unintended data access. Impact depends on the specific finding.",
  },
  "graphql": {
    financial: "Medium", operational: "Low", reputational: "Medium", legal: "Low",
    rationale: "GraphQL misconfigurations may expose the full API schema or enable denial-of-service. Impact escalates if injection is possible.",
  },
  "authorization": {
    financial: "High", operational: "High", reputational: "High", legal: "High",
    rationale: "Broken access control may allow privilege escalation, unauthorized data access, and full system compromise. Regulatory impact under GDPR, PCI DSS.",
  },
  "sca": {
    financial: "High", operational: "High", reputational: "High", legal: "High",
    rationale: "Vulnerable dependencies may allow remote code execution, data breach, or denial of service. High regulatory impact due to supply chain risk.",
  },
  "ssrf": {
    financial: "High", operational: "High", reputational: "High", legal: "High",
    rationale: "SSRF may allow access to internal services, cloud metadata, and credential stores. May enable full infrastructure compromise.",
  },
};

function deriveBusinessImpact(category: string, severity: string): BusinessImpact | null {
  if (severity === "info" || category === "Tool Availability" || category === "Connectivity") return null;
  const profile = IMPACT_BY_CATEGORY[category.toLowerCase()];
  if (profile) return profile;

  const level: ImpactLevel = severity === "critical" ? "High" : severity === "high" ? "High" : severity === "medium" ? "Medium" : "Low";
  return {
    financial: level, operational: level, reputational: level, legal: level,
    rationale: "Impact assessment derived from finding severity. Review in context of the specific vulnerability.",
  };
}

// ─── Remediation Complexity & Priority ────────────────────────────────────────

const COMPLEXITY_BY_CATEGORY: Record<string, RemediationComplexity> = {
  "security headers":         "Low",
  "security misconfiguration": "Low",
  "information disclosure":    "Low",
  "cors":                      "Low",
  "authentication":            "High",
  "sql injection":             "Medium",
  "cross-site scripting":      "Medium",
  "xss":                       "Medium",
  "path traversal":            "Medium",
  "nikto":                     "Medium",
  "nuclei":                    "Medium",
  "owasp zap":                 "Medium",
  "tls":                       "Medium",
  "business logic":            "Medium",
  "graphql":                   "Low",
  "authorization":             "High",
  "sca":                       "Low",
  "ssrf":                      "Medium",
};

function deriveRemediationComplexity(category: string): RemediationComplexity {
  return COMPLEXITY_BY_CATEGORY[category.toLowerCase()] ?? "Medium";
}

function deriveRemediationPriority(severity: string, cvssScore: number | null): RemediationPriority {
  const score = cvssScore ?? 0;
  if (severity === "critical" || score >= 9.0) return "P1";
  if (severity === "high" || score >= 7.0) return "P1";
  if (severity === "medium" || score >= 4.0) return "P2";
  if (severity === "low") return "P3";
  return "P4";
}

// ─── MITRE ATT&CK ────────────────────────────────────────────────────────────

const ATTACK_BY_CWE: Record<string, AttackTechnique[]> = {
  "CWE-89":  [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "CWE-79":  [{ techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
              { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" }],
  "CWE-22":  [{ techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
              { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" }],
  "CWE-307": [{ techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" }],
  "CWE-203": [{ techniqueId: "T1087", techniqueName: "Account Discovery", tactic: "Discovery" }],
  "CWE-538": [{ techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" }],
  "CWE-942": [{ techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" }],
  "CWE-693": [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "CWE-311": [{ techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Credential Access" }],
  "CWE-326": [{ techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Credential Access" }],
  "CWE-295": [{ techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Credential Access" }],
  "CWE-319": [{ techniqueId: "T1040", techniqueName: "Network Sniffing", tactic: "Credential Access" }],
  "CWE-352": [{ techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" }],
  "CWE-915": [{ techniqueId: "T1098", techniqueName: "Account Manipulation", tactic: "Persistence" }],
  "CWE-215": [{ techniqueId: "T1592", techniqueName: "Gather Victim Host Information", tactic: "Reconnaissance" }],
  "CWE-209": [{ techniqueId: "T1592", techniqueName: "Gather Victim Host Information", tactic: "Reconnaissance" }],
  "CWE-770": [{ techniqueId: "T1499", techniqueName: "Endpoint Denial of Service", tactic: "Impact" }],
  "CWE-400": [{ techniqueId: "T1499", techniqueName: "Endpoint Denial of Service", tactic: "Impact" }],
  "CWE-200": [{ techniqueId: "T1592", techniqueName: "Gather Victim Host Information", tactic: "Reconnaissance" }],
  "CWE-1021": [{ techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" }],
  "CWE-269":  [{ techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Privilege Escalation" }],
  "CWE-284":  [{ techniqueId: "T1550", techniqueName: "Use Alternate Authentication Material", tactic: "Defense Evasion" }],
  "CWE-639":  [{ techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Privilege Escalation" }],
  "CWE-502":  [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "CWE-918":  [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "CWE-1104": [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
};

const ATTACK_BY_CATEGORY: Record<string, AttackTechnique[]> = {
  "sql injection":         [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "cross-site scripting":  [{ techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" }],
  "xss":                   [{ techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" }],
  "authentication":        [{ techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" }],
  "cors":                  [{ techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" }],
  "path traversal":        [{ techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" }],
  "information disclosure":[{ techniqueId: "T1592", techniqueName: "Gather Victim Host Information", tactic: "Reconnaissance" }],
  "security headers":      [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "security misconfiguration": [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "tls":                       [{ techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Credential Access" }],
  "business logic":            [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "graphql":                   [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "authorization":             [{ techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Privilege Escalation" },
                                { techniqueId: "T1550", techniqueName: "Use Alternate Authentication Material", tactic: "Defense Evasion" }],
  "sca":                       [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
                                { techniqueId: "T1195", techniqueName: "Supply Chain Compromise", tactic: "Initial Access" }],
  "ssrf":                      [{ techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }],
};

function deriveAttackTechniques(category: string, cweId?: string | null): AttackTechnique[] | null {
  if (category === "Tool Availability" || category === "Connectivity") return null;
  const techniques = (cweId ? ATTACK_BY_CWE[cweId] : null) ?? ATTACK_BY_CATEGORY[category.toLowerCase()] ?? null;
  return techniques;
}

// ─── ISO 27001 Annex A ────────────────────────────────────────────────────────

interface Iso27001Control { control: string; title: string; }

const ISO_BY_CATEGORY: Record<string, Iso27001Control[]> = {
  "sql injection":          [{ control: "A.14.2.5", title: "Secure system engineering principles" }],
  "cross-site scripting":   [{ control: "A.14.2.5", title: "Secure system engineering principles" }],
  "xss":                    [{ control: "A.14.2.5", title: "Secure system engineering principles" }],
  "authentication":         [{ control: "A.9.4.2",  title: "Secure log-on procedures" },
                             { control: "A.9.4.3",  title: "Password management system" }],
  "cors":                   [{ control: "A.14.1.2", title: "Securing application services on public networks" }],
  "path traversal":         [{ control: "A.14.2.5", title: "Secure system engineering principles" },
                             { control: "A.12.6.1", title: "Management of technical vulnerabilities" }],
  "security headers":       [{ control: "A.14.1.2", title: "Securing application services on public networks" }],
  "security misconfiguration": [{ control: "A.12.5.1", title: "Installation of software on operational systems" },
                                { control: "A.12.6.1", title: "Management of technical vulnerabilities" }],
  "information disclosure": [{ control: "A.12.6.1", title: "Management of technical vulnerabilities" },
                             { control: "A.18.1.4", title: "Privacy and protection of PII" }],
  "nikto":                  [{ control: "A.12.6.1", title: "Management of technical vulnerabilities" }],
  "nuclei":                 [{ control: "A.12.6.1", title: "Management of technical vulnerabilities" }],
  "owasp zap":              [{ control: "A.14.2.8", title: "System security testing" }],
  "tls":                    [{ control: "A.10.1.1", title: "Policy on the use of cryptographic controls" },
                             { control: "A.14.1.2", title: "Securing application services on public networks" }],
  "business logic":         [{ control: "A.14.2.5", title: "Secure system engineering principles" },
                             { control: "A.14.2.8", title: "System security testing" }],
  "graphql":                [{ control: "A.14.2.5", title: "Secure system engineering principles" },
                             { control: "A.14.1.2", title: "Securing application services on public networks" }],
  "authorization":          [{ control: "A.9.4.1", title: "Information access restriction" },
                             { control: "A.9.4.2", title: "Secure log-on procedures" },
                             { control: "A.14.2.5", title: "Secure system engineering principles" }],
  "sca":                    [{ control: "A.12.5.1", title: "Installation of software on operational systems" },
                             { control: "A.12.6.1", title: "Management of technical vulnerabilities" },
                             { control: "A.14.2.5", title: "Secure system engineering principles" }],
  "ssrf":                   [{ control: "A.14.2.5", title: "Secure system engineering principles" },
                             { control: "A.14.1.2", title: "Securing application services on public networks" }],
};

function deriveIso27001Controls(category: string): string[] | null {
  if (category === "Tool Availability" || category === "Connectivity") return null;
  const controls = ISO_BY_CATEGORY[category.toLowerCase()];
  if (!controls) return ["A.12.6.1"];
  return controls.map((c) => c.control);
}

export function getIso27001ControlTitle(control: string): string {
  const titles: Record<string, string> = {
    "A.9.4.1":  "Information access restriction",
    "A.9.4.2":  "Secure log-on procedures",
    "A.9.4.3":  "Password management system",
    "A.10.1.1": "Policy on the use of cryptographic controls",
    "A.12.5.1": "Installation of software on operational systems",
    "A.12.6.1": "Management of technical vulnerabilities",
    "A.14.1.2": "Securing application services on public networks",
    "A.14.2.5": "Secure system engineering principles",
    "A.14.2.8": "System security testing",
    "A.18.1.4": "Privacy and protection of PII",
  };
  return titles[control] ?? control;
}

// ─── OWASP API Security Top 10:2023 ───────────────────────────────────────────

export interface ApiSecurityMapping {
  id: string;       // e.g. "API2:2023"
  name: string;     // e.g. "Broken Authentication"
}

const API_SECURITY_BY_CWE: Record<string, ApiSecurityMapping> = {
  "CWE-307": { id: "API2:2023", name: "Broken Authentication" },
  "CWE-203": { id: "API2:2023", name: "Broken Authentication" },
  "CWE-915": { id: "API3:2023", name: "Broken Object Property Level Authorization" },
  "CWE-352": { id: "API3:2023", name: "Broken Object Property Level Authorization" },
  "CWE-770": { id: "API4:2023", name: "Unrestricted Resource Consumption" },
  "CWE-400": { id: "API4:2023", name: "Unrestricted Resource Consumption" },
  "CWE-215": { id: "API8:2023", name: "Security Misconfiguration" },
  "CWE-209": { id: "API8:2023", name: "Security Misconfiguration" },
  "CWE-693": { id: "API8:2023", name: "Security Misconfiguration" },
  "CWE-942": { id: "API8:2023", name: "Security Misconfiguration" },
  "CWE-1021": { id: "API8:2023", name: "Security Misconfiguration" },
  "CWE-200": { id: "API9:2023", name: "Improper Inventory Management" },
  "CWE-538": { id: "API9:2023", name: "Improper Inventory Management" },
  "CWE-269": { id: "API1:2023", name: "Broken Object Level Authorization" },
  "CWE-639": { id: "API1:2023", name: "Broken Object Level Authorization" },
  "CWE-284": { id: "API5:2023", name: "Broken Function Level Authorization" },
  "CWE-502": { id: "API10:2023", name: "Unsafe Consumption of APIs" },
  "CWE-918": { id: "API7:2023", name: "Server Side Request Forgery" },
  "CWE-1104": { id: "API10:2023", name: "Unsafe Consumption of APIs" },
};

const API_SECURITY_BY_CATEGORY: Record<string, ApiSecurityMapping> = {
  "sca":                      { id: "API10:2023", name: "Unsafe Consumption of APIs" },
  "ssrf":                     { id: "API7:2023", name: "Server Side Request Forgery" },
  "authorization":            { id: "API1:2023", name: "Broken Object Level Authorization" },
  "authentication":           { id: "API2:2023", name: "Broken Authentication" },
  "business logic":           { id: "API6:2023", name: "Unrestricted Access to Sensitive Business Flows" },
  "graphql":                  { id: "API4:2023", name: "Unrestricted Resource Consumption" },
  "cors":                     { id: "API8:2023", name: "Security Misconfiguration" },
  "security headers":         { id: "API8:2023", name: "Security Misconfiguration" },
  "security misconfiguration": { id: "API8:2023", name: "Security Misconfiguration" },
  "information disclosure":   { id: "API9:2023", name: "Improper Inventory Management" },
  "sql injection":            { id: "API3:2023", name: "Broken Object Property Level Authorization" },
  "cross-site scripting":     { id: "API8:2023", name: "Security Misconfiguration" },
  "xss":                      { id: "API8:2023", name: "Security Misconfiguration" },
  "path traversal":           { id: "API8:2023", name: "Security Misconfiguration" },
  "tls":                      { id: "API8:2023", name: "Security Misconfiguration" },
};

/** Derive OWASP API Security Top 10:2023 category from finding metadata. Computed at report time. */
export function deriveApiSecurityCategory(category: string, cweId?: string | null): ApiSecurityMapping | null {
  if (category === "Tool Availability" || category === "Connectivity") return null;
  return (cweId ? API_SECURITY_BY_CWE[cweId] : null) ?? API_SECURITY_BY_CATEGORY[category.toLowerCase()] ?? null;
}

// ─── Main enrichment function ─────────────────────────────────────────────────

export function enrichFinding(
  category: string,
  severity: string,
  cweId?: string | null,
): EnrichedFields {
  const cvss = deriveCvss(category, severity, cweId);
  const impact = deriveBusinessImpact(category, severity);
  const complexity = (severity === "info" || category === "Tool Availability" || category === "Connectivity")
    ? null : deriveRemediationComplexity(category);
  const priority = (severity === "info" || category === "Tool Availability" || category === "Connectivity")
    ? null : deriveRemediationPriority(severity, cvss?.baseScore ?? null);
  const techniques = deriveAttackTechniques(category, cweId);
  const isoControls = deriveIso27001Controls(category);

  return {
    cvssVector: cvss?.vectorString ?? null,
    cvssScore: cvss?.baseScore ?? null,
    businessImpact: impact,
    remediationComplexity: complexity,
    remediationPriority: priority,
    attackTechniques: techniques,
    iso27001Controls: isoControls,
  };
}
