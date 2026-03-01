import { beforeAll, describe, expect, it, vi } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../db", () => ({
  upsertUser: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("./sdk", () => ({
  sdk: {
    createSessionToken: vi.fn().mockResolvedValue("dev-token"),
  },
}));

import * as db from "../db";

describe("GET /api/dev-login", () => {
  let registerDevAuthRoutes: (app: express.Express) => void;

  beforeAll(async () => {
    vi.resetModules();
    process.env.DEV_BYPASS_AUTH = "true";
    process.env.DATABASE_URL = "mysql://localhost:3306/test";
    const mod = await import("./devAuth");
    registerDevAuthRoutes = mod.registerDevAuthRoutes;
  });

  it("returns 302 and redirects when DATABASE_URL is set", async () => {
    const app = express();
    registerDevAuthRoutes(app);
    const res = await request(app).get("/api/dev-login");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBeDefined();
  });

  it("returns 500 when db or sdk throws", async () => {
    vi.mocked(db.upsertUser).mockRejectedValueOnce(new Error("DB error"));
    const app = express();
    registerDevAuthRoutes(app);
    const res = await request(app).get("/api/dev-login");
    expect(res.status).toBe(500);
    expect(res.body?.error).toMatch(/failed/);
  });

  it("returns 503 when DATABASE_URL is unset", async () => {
    vi.resetModules();
    process.env.DEV_BYPASS_AUTH = "true";
    delete process.env.DATABASE_URL;
    const { registerDevAuthRoutes: register } = await import("./devAuth");
    const app = express();
    register(app);
    const res = await request(app).get("/api/dev-login");
    expect(res.status).toBe(503);
    expect(res.body?.error).toMatch(/DATABASE_URL/);
    process.env.DATABASE_URL = "mysql://localhost:3306/test";
  });
});
