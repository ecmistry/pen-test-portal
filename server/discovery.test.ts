import { describe, expect, it } from "vitest";
import {
  classifyDiscoveredRoutes,
  dedupeRoutes,
  parseHtmlLinks,
  parseJsRouteHints,
  parseRobotsTxt,
  parseSitemapXml,
} from "./discovery";
import { getScanQueueStats, enqueueScan, setScanMaxConcurrent } from "./scanQueue";
import { createLegacyOobSession } from "./interactsh";

describe("discovery parsers", () => {
  it("parses robots and sitemap", () => {
    const robots = parseRobotsTxt("Disallow: /admin\nSitemap: https://ex.com/app\n", "https://ex.com");
    expect(robots.some((r) => r.path === "/admin")).toBe(true);
    const sm = parseSitemapXml("<urlset><url><loc>https://ex.com/users/1</loc></url></urlset>", "https://ex.com");
    expect(sm[0]?.path).toBe("/users/1");
  });

  it("parses html and js routes", () => {
    const html = parseHtmlLinks(`<a href="/dashboard">x</a><link href="/assets/a.css">`, "https://ex.com");
    expect(html.some((r) => r.path === "/dashboard")).toBe(true);
    const js = parseJsRouteHints(`const r = { path: "/api/users/{id}" }; route("/admin/settings");`);
    expect(js.length).toBeGreaterThan(0);
    const classified = classifyDiscoveredRoutes(dedupeRoutes([...html, ...js]));
    expect(classified.allPaths.length).toBeGreaterThan(0);
  });
});

describe("scanQueue", () => {
  it("reports stats and respects concurrency", async () => {
    setScanMaxConcurrent(1);
    let started = 0;
    let finished = 0;
    const p1 = enqueueScan(async () => {
      started++;
      await new Promise((r) => setTimeout(r, 30));
      finished++;
    });
    const p2 = enqueueScan(async () => {
      started++;
      finished++;
    });
    // while first running, waiting should be >= 0
    await new Promise((r) => setTimeout(r, 5));
    const mid = getScanQueueStats();
    expect(mid.maxConcurrent).toBe(1);
    await Promise.all([p1, p2]);
    expect(started).toBe(2);
    expect(finished).toBe(2);
  });
});

describe("interactsh legacy session", () => {
  it("builds callback urls", () => {
    const s = createLegacyOobSession("https://oast.example");
    const url = s.makeCallbackUrl("probe1");
    expect(url).toContain("probe1");
    expect(url).toContain("oast.example");
  });
});
