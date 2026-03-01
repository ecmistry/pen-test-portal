import { beforeAll, describe, expect, it, vi } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../db", () => ({
  upsertUser: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("./sdk", () => ({
  sdk: {
    createSessionToken: vi.fn().mockResolvedValue("fake-session-token"),
  },
}));

import * as db from "../db";

describe("POST /api/login", () => {
  let registerAdminAuthRoutes: (app: express.Express) => void;

  beforeAll(async () => {
    vi.resetModules();
    process.env.ADMIN_EMAIL = "admin@test.com";
    process.env.ADMIN_PASSWORD = "testpass";
    process.env.DATABASE_URL = "mysql://localhost:3306/test";
    const mod = await import("./adminAuth");
    registerAdminAuthRoutes = mod.registerAdminAuthRoutes;
  });

  function createApp(): express.Express {
    const app = express();
    app.use(express.json());
    registerAdminAuthRoutes(app);
    return app;
  }

  it("returns 400 when Content-Type is not JSON", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/login")
      .set("Content-Type", "text/plain")
      .send("email=admin@test.com&password=testpass");
    expect(res.status).toBe(400);
    expect(res.body?.success).toBe(false);
    expect(res.body?.error).toMatch(/JSON/i);
  });

  it("returns 401 for invalid credentials", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/login")
      .set("Content-Type", "application/json")
      .send({ email: "admin@test.com", password: "wrong" });
    expect(res.status).toBe(401);
    expect(res.body?.success).toBe(false);
    expect(res.body?.error).toMatch(/invalid|password/i);
  });

  it("returns 500 when db.upsertUser or sdk.createSessionToken throws", async () => {
    vi.mocked(db.upsertUser).mockRejectedValueOnce(new Error("DB error"));
    const app = createApp();
    const res = await request(app)
      .post("/api/login")
      .set("Content-Type", "application/json")
      .send({ email: "admin@test.com", password: "testpass" });
    expect(res.status).toBe(500);
    expect(res.body?.success).toBe(false);
  });

  it("returns 200 and sets cookie for valid credentials", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/login")
      .set("Content-Type", "application/json")
      .send({ email: "admin@test.com", password: "testpass" });
    expect(res.status).toBe(200);
    expect(res.body?.success).toBe(true);
    const setCookie = res.headers["set-cookie"];
    expect(Array.isArray(setCookie)).toBe(true);
    expect(setCookie?.some((c: string) => c.includes("app_session_id") || c.includes("fake-session-token"))).toBe(true);
  });

  it("returns 503 when login not configured (no ADMIN_EMAIL)", async () => {
    vi.resetModules();
    const origEmail = process.env.ADMIN_EMAIL;
    const origDb = process.env.DATABASE_URL;
    delete process.env.ADMIN_EMAIL;
    process.env.ADMIN_PASSWORD = "x";
    process.env.DATABASE_URL = "mysql://localhost:3306/test";
    const { registerAdminAuthRoutes: register } = await import("./adminAuth");
    const app = express();
    app.use(express.json());
    register(app);
    const res = await request(app)
      .post("/api/login")
      .set("Content-Type", "application/json")
      .send({ email: "a@b.com", password: "x" });
    expect(res.status).toBe(503);
    expect(res.body?.error).toMatch(/not configured/i);
    process.env.ADMIN_EMAIL = origEmail;
    process.env.DATABASE_URL = origDb;
  });

  it("returns 503 when DATABASE_URL is unset", async () => {
    vi.resetModules();
    const origDb = process.env.DATABASE_URL;
    process.env.ADMIN_EMAIL = "admin@test.com";
    process.env.ADMIN_PASSWORD = "testpass";
    delete process.env.DATABASE_URL;
    const { registerAdminAuthRoutes: register } = await import("./adminAuth");
    const app = express();
    app.use(express.json());
    register(app);
    const res = await request(app)
      .post("/api/login")
      .set("Content-Type", "application/json")
      .send({ email: "admin@test.com", password: "testpass" });
    expect(res.status).toBe(503);
    expect(res.body?.error).toMatch(/database|not configured/i);
    process.env.DATABASE_URL = origDb;
  });
});

describe("GET /api/admin-login and POST /api/admin-login", () => {
  let registerAdminAuthRoutes: (app: express.Express) => void;

  beforeAll(async () => {
    vi.resetModules();
    process.env.ADMIN_EMAIL = "admin@test.com";
    process.env.ADMIN_PASSWORD = "testpass";
    process.env.DATABASE_URL = "mysql://localhost:3306/test";
    const mod = await import("./adminAuth");
    registerAdminAuthRoutes = mod.registerAdminAuthRoutes;
  });

  function createApp(): express.Express {
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    registerAdminAuthRoutes(app);
    return app;
  }

  it("GET /api/admin-login returns HTML login form", async () => {
    const app = createApp();
    const res = await request(app).get("/api/admin-login");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/html/);
    expect(res.text).toContain("Admin Login");
    expect(res.text).toContain("/api/admin-login");
  });

  it("POST /api/admin-login with form returns 302 and redirects when valid", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/admin-login")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("email=admin@test.com&password=testpass");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBeDefined();
  });

  it("POST /api/admin-login with JSON returns 302 when valid", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/admin-login")
      .set("Content-Type", "application/json")
      .send({ email: "admin@test.com", password: "testpass" });
    expect(res.status).toBe(302);
  });

  it("POST /api/admin-login returns 400 when Content-Type is not form or JSON", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/admin-login")
      .set("Content-Type", "text/plain")
      .send("email=admin@test.com&password=testpass");
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/JSON|form/i);
  });

  it("POST /api/admin-login returns 500 when db or sdk throws", async () => {
    vi.mocked(db.upsertUser).mockRejectedValueOnce(new Error("DB error"));
    const app = createApp();
    const res = await request(app)
      .post("/api/admin-login")
      .set("Content-Type", "application/json")
      .send({ email: "admin@test.com", password: "testpass" });
    expect(res.status).toBe(500);
    expect(res.text).toMatch(/Login failed/);
  });

  it("POST /api/admin-login returns 401 for invalid credentials", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/admin-login")
      .set("Content-Type", "application/json")
      .send({ email: "admin@test.com", password: "wrong" });
    expect(res.status).toBe(401);
    expect(res.text).toMatch(/Invalid/i);
  });
});
