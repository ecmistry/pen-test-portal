/**
 * Vulnerability intelligence lookups — CISA KEV, EPSS, and NVD (cached).
 * Data is refreshed by penTestUpdater / the 03:00 UTC capability cron.
 */

import fs from "fs/promises";
import path from "path";
import { gunzipSync } from "zlib";

const USER_AGENT = "Ghoststrike-PenTestPortal/1.0 (security-research; +https://ghoststrike.tech)";

export const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/** Official EPSS current scores (gzipped CSV: cve,epss,percentile) */
export const EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
export const NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export interface KevEntry {
  cveId: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: string;
  shortDescription?: string;
}

export interface EpssEntry {
  epss: number;
  percentile: number;
}

export interface NvdEntry {
  cveId: string;
  description?: string;
  cvssScore?: number;
  cvssVector?: string;
  cvssVersion?: string;
  published?: string;
  lastModified?: string;
  references?: string[];
  fetchedAt: string;
}

export interface VulnIntelSnapshot {
  kevCount: number;
  epssCount: number;
  nvdCacheCount: number;
  lastUpdated?: string;
}

export interface CveIntel {
  cveId: string;
  inKev: boolean;
  kev?: KevEntry;
  epss?: EpssEntry;
  nvd?: NvdEntry;
}

function intelDir(): string {
  return path.join(process.cwd(), "data", "vuln-intel");
}

function kevPath(): string {
  return path.join(intelDir(), "kev.json");
}
function epssPath(): string {
  return path.join(intelDir(), "epss.json");
}
function nvdCachePath(): string {
  return path.join(intelDir(), "nvd-cache.json");
}
function metaPath(): string {
  return path.join(intelDir(), "meta.json");
}

async function ensureIntelDir(): Promise<void> {
  await fs.mkdir(intelDir(), { recursive: true });
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function extractCveIds(...texts: Array<string | null | undefined>): string[] {
  const found = new Set<string>();
  const re = /\bCVE-\d{4}-\d{4,}\b/gi;
  for (const text of texts) {
    if (!text) continue;
    const matches = Array.from(text.matchAll(re));
    for (const m of matches) {
      found.add(m[0].toUpperCase());
    }
  }
  return Array.from(found);
}

export async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: {
      "User-Agent": USER_AGENT,
      Accept: "application/json",
      ...(init?.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${url}`);
  return res.json() as Promise<T>;
}

export async function fetchBuffer(url: string): Promise<Buffer> {
  const res = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${url}`);
  const ab = await res.arrayBuffer();
  return Buffer.from(ab);
}

/** Parse EPSS CSV (optionally gzipped). Header: cve,epss,percentile */
export function parseEpssCsv(text: string): Record<string, EpssEntry> {
  const out: Record<string, EpssEntry> = {};
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (!line || line.startsWith("#") || line.toLowerCase().startsWith("cve,")) continue;
    const [cve, epssStr, pctStr] = line.split(",");
    if (!cve || !cve.toUpperCase().startsWith("CVE-")) continue;
    const epss = Number(epssStr);
    const percentile = Number(pctStr);
    if (!Number.isFinite(epss)) continue;
    out[cve.toUpperCase()] = {
      epss,
      percentile: Number.isFinite(percentile) ? percentile : 0,
    };
  }
  return out;
}

export function parseKevCatalog(data: {
  vulnerabilities?: Array<Record<string, string>>;
}): Record<string, KevEntry> {
  const out: Record<string, KevEntry> = {};
  for (const v of data.vulnerabilities || []) {
    const cveId = (v.cveID || v.cveId || "").toUpperCase();
    if (!cveId.startsWith("CVE-")) continue;
    out[cveId] = {
      cveId,
      vendorProject: v.vendorProject,
      product: v.product,
      vulnerabilityName: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      requiredAction: v.requiredAction,
      knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
      shortDescription: v.shortDescription,
    };
  }
  return out;
}

export function parseNvdCveResponse(data: any, cveId: string): NvdEntry | null {
  const item = data?.vulnerabilities?.[0]?.cve;
  if (!item) return null;

  const descriptions: Array<{ lang?: string; value?: string }> = item.descriptions || [];
  const description =
    descriptions.find((d) => d.lang === "en")?.value || descriptions[0]?.value || undefined;

  let cvssScore: number | undefined;
  let cvssVector: string | undefined;
  let cvssVersion: string | undefined;
  const metrics = item.metrics || {};
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const v2 = metrics.cvssMetricV2?.[0]?.cvssData;
  const chosen = v31 || v30 || v2;
  if (chosen) {
    cvssScore = typeof chosen.baseScore === "number" ? chosen.baseScore : undefined;
    cvssVector = chosen.vectorString;
    cvssVersion = chosen.version;
  }

  const references = (item.references || [])
    .map((r: { url?: string }) => r.url)
    .filter(Boolean)
    .slice(0, 8) as string[];

  return {
    cveId: cveId.toUpperCase(),
    description,
    cvssScore,
    cvssVector,
    cvssVersion,
    published: item.published,
    lastModified: item.lastModified,
    references,
    fetchedAt: new Date().toISOString(),
  };
}

export async function updateKevCatalog(): Promise<{ count: number; error?: string }> {
  try {
    await ensureIntelDir();
    const data = await fetchJson<{ vulnerabilities?: Array<Record<string, string>> }>(CISA_KEV_URL);
    const map = parseKevCatalog(data);
    await fs.writeFile(kevPath(), JSON.stringify(map), "utf-8");
    return { count: Object.keys(map).length };
  } catch (err: unknown) {
    return { count: 0, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function updateEpssScores(): Promise<{ count: number; error?: string }> {
  try {
    await ensureIntelDir();
    const buf = await fetchBuffer(EPSS_CSV_URL);
    let text: string;
    try {
      text = gunzipSync(buf).toString("utf-8");
    } catch {
      text = buf.toString("utf-8");
    }
    const map = parseEpssCsv(text);
    await fs.writeFile(epssPath(), JSON.stringify(map), "utf-8");
    return { count: Object.keys(map).length };
  } catch (err: unknown) {
    return { count: 0, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Pre-warm NVD cache for CISA KEV CVEs (highest-priority vulns).
 * Limited batch to respect NVD rate limits; expands over successive daily runs.
 */
export async function warmNvdForKev(limit = Number(process.env.NVD_KEV_WARM_LIMIT || 25)): Promise<{
  fetched: number;
  cached: number;
  error?: string;
}> {
  try {
    const kev = await loadKev(true);
    // Prefer most recently added KEV entries
    const ids = Object.values(kev)
      .sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")))
      .map((e) => e.cveId);
    const before = Object.keys(await loadNvdCache()).length;
    await enrichNvdForCves(ids, {
      maxFetches: Math.max(0, limit),
      minIntervalMs: process.env.NVD_API_KEY ? 700 : 6500,
    });
    const after = Object.keys(await loadNvdCache()).length;
    return { fetched: Math.max(0, after - before), cached: after };
  } catch (err: unknown) {
    return { fetched: 0, cached: 0, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function writeIntelMeta(extra: Record<string, unknown> = {}): Promise<void> {
  await ensureIntelDir();
  const existing = (await readJsonFile<Record<string, unknown>>(metaPath())) || {};
  await fs.writeFile(
    metaPath(),
    JSON.stringify({ ...existing, ...extra, lastUpdated: new Date().toISOString() }, null, 2),
    "utf-8"
  );
}

let kevMem: Record<string, KevEntry> | null = null;
let epssMem: Record<string, EpssEntry> | null = null;
let nvdMem: Record<string, NvdEntry> | null = null;
let kevLoadedAt = 0;
let epssLoadedAt = 0;

async function loadKev(force = false): Promise<Record<string, KevEntry>> {
  if (!force && kevMem && Date.now() - kevLoadedAt < 60_000) return kevMem;
  kevMem = (await readJsonFile<Record<string, KevEntry>>(kevPath())) || {};
  kevLoadedAt = Date.now();
  return kevMem;
}

async function loadEpss(force = false): Promise<Record<string, EpssEntry>> {
  if (!force && epssMem && Date.now() - epssLoadedAt < 60_000) return epssMem;
  epssMem = (await readJsonFile<Record<string, EpssEntry>>(epssPath())) || {};
  epssLoadedAt = Date.now();
  return epssMem;
}

async function loadNvdCache(): Promise<Record<string, NvdEntry>> {
  if (nvdMem) return nvdMem;
  nvdMem = (await readJsonFile<Record<string, NvdEntry>>(nvdCachePath())) || {};
  return nvdMem;
}

async function saveNvdCache(cache: Record<string, NvdEntry>): Promise<void> {
  await ensureIntelDir();
  nvdMem = cache;
  await fs.writeFile(nvdCachePath(), JSON.stringify(cache), "utf-8");
}

export async function getVulnIntelSnapshot(): Promise<VulnIntelSnapshot> {
  const [kev, epss, nvd, meta] = await Promise.all([
    loadKev(true),
    loadEpss(true),
    loadNvdCache(),
    readJsonFile<{ lastUpdated?: string }>(metaPath()),
  ]);
  return {
    kevCount: Object.keys(kev).length,
    epssCount: Object.keys(epss).length,
    nvdCacheCount: Object.keys(nvd).length,
    lastUpdated: meta?.lastUpdated,
  };
}

export async function lookupCveIntel(cveId: string): Promise<CveIntel> {
  const id = cveId.toUpperCase();
  const [kev, epss] = await Promise.all([loadKev(), loadEpss()]);
  const nvd = await loadNvdCache();
  return {
    cveId: id,
    inKev: Boolean(kev[id]),
    kev: kev[id],
    epss: epss[id],
    nvd: nvd[id],
  };
}

/** Fetch NVD details for missing CVE IDs (rate-limited). Returns updated cache entries. */
export async function enrichNvdForCves(
  cveIds: string[],
  opts: { maxFetches?: number; minIntervalMs?: number } = {}
): Promise<Record<string, NvdEntry>> {
  const maxFetches = opts.maxFetches ?? 15;
  const minIntervalMs = opts.minIntervalMs ?? 6500; // NVD public rate ~5/30s without API key
  const cache = await loadNvdCache();
  const missing = cveIds.map((c) => c.toUpperCase()).filter((id) => id.startsWith("CVE-") && !cache[id]);
  const toFetch = missing.slice(0, maxFetches);
  if (toFetch.length === 0) return cache;

  const apiKey = process.env.NVD_API_KEY?.trim();
  const interval = apiKey ? 700 : minIntervalMs;

  for (let i = 0; i < toFetch.length; i++) {
    const cveId = toFetch[i];
    try {
      const url = `${NVD_CVE_API}?cveId=${encodeURIComponent(cveId)}`;
      const data = await fetchJson<any>(url, {
        headers: apiKey ? { apiKey } : undefined,
      });
      const parsed = parseNvdCveResponse(data, cveId);
      if (parsed) cache[cveId] = parsed;
    } catch (err) {
      console.warn(`[vulnIntel] NVD fetch failed for ${cveId}:`, (err as Error).message);
    }
    if (i < toFetch.length - 1) {
      await new Promise((r) => setTimeout(r, interval));
    }
  }

  await saveNvdCache(cache);
  return cache;
}

export interface AppliedThreatIntel {
  cveIds: string[];
  inKev: boolean;
  kevDueDate?: string;
  epss?: number;
  epssPercentile?: number;
  nvdCvssScore?: number;
  nvdCvssVector?: string;
  nvdDescription?: string;
  exploitDbUrls: string[];
  evidenceExtra: string;
  descriptionExtra: string;
  recommendationExtra: string;
  /** Prefer this CVSS over heuristic enrichment when present */
  preferCvss?: { score: number; vector: string };
  bumpPriorityToP1: boolean;
  confidenceHint?: "confirmed" | "likely" | "heuristic";
}

export async function buildThreatIntelForTexts(
  texts: Array<string | null | undefined>,
  opts: { fetchMissingNvd?: boolean } = {}
): Promise<AppliedThreatIntel | null> {
  const cveIds = extractCveIds(...texts);
  if (cveIds.length === 0) return null;

  if (opts.fetchMissingNvd !== false) {
    await enrichNvdForCves(cveIds);
  }

  const intelList = await Promise.all(cveIds.map((id) => lookupCveIntel(id)));
  const kevHits = intelList.filter((i) => i.inKev);
  const bestEpss = intelList
    .filter((i) => i.epss)
    .sort((a, b) => (b.epss?.epss ?? 0) - (a.epss?.epss ?? 0))[0];
  const bestNvd = intelList.find((i) => i.nvd?.cvssScore != null) || intelList.find((i) => i.nvd);

  const evidenceLines: string[] = ["[Threat Intel]"];
  evidenceLines.push(`CVEs: ${cveIds.join(", ")}`);
  if (kevHits.length) {
    for (const k of kevHits) {
      evidenceLines.push(
        `CISA KEV: ${k.cveId}${k.kev?.dueDate ? ` (due ${k.kev.dueDate})` : ""}${
          k.kev?.knownRansomwareCampaignUse && k.kev.knownRansomwareCampaignUse !== "Unknown"
            ? ` ransomware=${k.kev.knownRansomwareCampaignUse}`
            : ""
        }`
      );
    }
  }
  if (bestEpss?.epss) {
    evidenceLines.push(
      `EPSS: ${bestEpss.cveId} score=${bestEpss.epss.epss.toFixed(5)} percentile=${bestEpss.epss.percentile.toFixed(5)}`
    );
  }
  if (bestNvd?.nvd) {
    if (bestNvd.nvd.cvssScore != null) {
      evidenceLines.push(
        `NVD CVSS: ${bestNvd.cveId} score=${bestNvd.nvd.cvssScore}${bestNvd.nvd.cvssVector ? ` vector=${bestNvd.nvd.cvssVector}` : ""}`
      );
    }
    if (bestNvd.nvd.references?.length) {
      evidenceLines.push(`NVD refs: ${bestNvd.nvd.references.slice(0, 3).join(" | ")}`);
    }
  }
  const exploitDbUrls = cveIds.map(
    (id) => `https://www.exploit-db.com/search?cve=${encodeURIComponent(id)}`
  );
  evidenceLines.push(`Exploit-DB search: ${exploitDbUrls[0]}`);

  const descParts: string[] = [];
  if (kevHits.length) {
    descParts.push(
      `Listed in CISA Known Exploited Vulnerabilities (KEV) catalog: ${kevHits.map((k) => k.cveId).join(", ")}.`
    );
  }
  if (bestNvd?.nvd?.description) {
    descParts.push(`NVD: ${bestNvd.nvd.description.slice(0, 500)}`);
  }
  if (bestEpss?.epss) {
    descParts.push(
      `EPSS exploit probability for ${bestEpss.cveId}: ${(bestEpss.epss.epss * 100).toFixed(2)}% (percentile ${(bestEpss.epss.percentile * 100).toFixed(1)}%).`
    );
  }

  const recParts: string[] = [];
  if (kevHits.length) {
    const due = kevHits[0].kev?.dueDate;
    recParts.push(
      `Prioritize remediation immediately — CISA KEV entry${due ? ` (due date ${due})` : ""}. ${
        kevHits[0].kev?.requiredAction || "Apply vendor patches or mitigations per CISA guidance."
      }`
    );
  }

  let confidenceHint: AppliedThreatIntel["confidenceHint"];
  const epssVal = bestEpss?.epss?.epss;
  if (kevHits.length || (epssVal != null && epssVal >= 0.5)) confidenceHint = "confirmed";
  else if (epssVal != null && epssVal >= 0.1) confidenceHint = "likely";

  let preferCvss: AppliedThreatIntel["preferCvss"];
  if (bestNvd?.nvd?.cvssScore != null && bestNvd.nvd.cvssVector) {
    preferCvss = { score: bestNvd.nvd.cvssScore, vector: bestNvd.nvd.cvssVector };
  }

  return {
    cveIds,
    inKev: kevHits.length > 0,
    kevDueDate: kevHits[0]?.kev?.dueDate,
    epss: bestEpss?.epss?.epss,
    epssPercentile: bestEpss?.epss?.percentile,
    nvdCvssScore: bestNvd?.nvd?.cvssScore,
    nvdCvssVector: bestNvd?.nvd?.cvssVector,
    nvdDescription: bestNvd?.nvd?.description,
    exploitDbUrls,
    evidenceExtra: evidenceLines.join("\n"),
    descriptionExtra: descParts.join(" "),
    recommendationExtra: recParts.join(" "),
    preferCvss,
    bumpPriorityToP1: kevHits.length > 0,
    confidenceHint,
  };
}

/** Test helpers */
export function clearVulnIntelMemoryCache(): void {
  kevMem = null;
  epssMem = null;
  nvdMem = null;
  kevLoadedAt = 0;
  epssLoadedAt = 0;
}
