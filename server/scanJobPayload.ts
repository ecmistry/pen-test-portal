/** Serializable scan job payload for durable queue recovery */
export type ScanJobPayload = {
  scanId: number;
  targetId: number;
  targetUrl: string;
  tools: string[];
  scanMode: "light" | "full" | string;
  authConfig?: unknown;
  manifestPath?: string | null;
  loginCredentials?: unknown;
  repoUrl?: string | null;
  openapiUrl?: string | null;
  /** When set, schedule runner may auto-push ticketing after completion */
  scheduleId?: number;
  userId?: number;
};
