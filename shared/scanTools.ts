/** Shared scan tool catalog for UI + API defaults */

export type ScanToolId =
  | "headers"
  | "auth"
  | "sqli"
  | "xss"
  | "recon"
  | "cors"
  | "traversal"
  | "config"
  | "logic"
  | "graphql"
  | "ssrf"
  | "tls"
  | "auth-roles"
  | "sca"
  | "sast"
  | "ai-prompt"
  | "secret-leak"
  | "url-norm"
  | "http-client"
  | "jwt"
  | "cookie-flags"
  | "smuggling"
  | "crlf"
  | "redirect"
  | "proto-pollution"
  | "nikto"
  | "nuclei"
  | "wapiti"
  | "zap";

export interface ScanToolOption {
  value: ScanToolId;
  label: string;
  group: "core" | "advanced" | "external";
  lightDefault?: boolean;
}

export const SCAN_TOOL_OPTIONS: ScanToolOption[] = [
  { value: "headers", label: "Security Headers", group: "core", lightDefault: true },
  { value: "auth", label: "Authentication", group: "core", lightDefault: true },
  { value: "sqli", label: "SQL Injection", group: "core", lightDefault: true },
  { value: "xss", label: "XSS", group: "core", lightDefault: true },
  { value: "recon", label: "Intelligence Gathering", group: "core", lightDefault: true },
  { value: "cors", label: "CORS", group: "advanced" },
  { value: "traversal", label: "Path Traversal", group: "advanced" },
  { value: "config", label: "HTTP Methods / Config", group: "advanced" },
  { value: "logic", label: "Business Logic", group: "advanced" },
  { value: "graphql", label: "GraphQL", group: "advanced" },
  { value: "ssrf", label: "SSRF", group: "advanced" },
  { value: "tls", label: "TLS / SSL", group: "advanced" },
  { value: "auth-roles", label: "Multi-Role AuthZ", group: "advanced" },
  { value: "sca", label: "SCA (Dependencies)", group: "advanced" },
  { value: "sast", label: "SAST (Semgrep)", group: "advanced" },
  { value: "ai-prompt", label: "AI Prompt Injection", group: "advanced" },
  { value: "secret-leak", label: "Secret Leak", group: "advanced" },
  { value: "url-norm", label: "URL Normalisation", group: "advanced" },
  { value: "http-client", label: "HTTP Client Config", group: "advanced" },
  { value: "jwt", label: "JWT Security", group: "advanced" },
  { value: "cookie-flags", label: "Cookie Flags", group: "advanced" },
  { value: "smuggling", label: "Request Smuggling", group: "advanced" },
  { value: "crlf", label: "CRLF Injection", group: "advanced" },
  { value: "redirect", label: "Open Redirect", group: "advanced" },
  { value: "proto-pollution", label: "Prototype Pollution", group: "advanced" },
  { value: "nikto", label: "Nikto", group: "external" },
  { value: "nuclei", label: "Nuclei", group: "external" },
  { value: "wapiti", label: "Wapiti", group: "external" },
  { value: "zap", label: "OWASP ZAP", group: "external" },
];

export const LIGHT_DEFAULT_TOOLS = SCAN_TOOL_OPTIONS.filter((t) => t.lightDefault).map((t) => t.value);

export const FULL_MODE_EXTRA_TOOLS = SCAN_TOOL_OPTIONS
  .filter((t) => !t.lightDefault)
  .map((t) => t.value);
