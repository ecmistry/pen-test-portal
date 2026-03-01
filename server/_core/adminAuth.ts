import { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";
import type { Express, Request, Response } from "express";
import * as db from "../db";
import { getSessionCookieOptions } from "./cookies";
import { ENV } from "./env";
import { sdk } from "./sdk";

const ADMIN_LOGIN_HTML = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Admin Login</title></head>
<body style="font-family:sans-serif;max-width:320px;margin:2rem auto;padding:1rem;">
  <h2>Admin Login</h2>
  <form method="post" action="/api/admin-login">
    <p><label>Email<br><input type="email" name="email" required style="width:100%;padding:0.5rem;"></label></p>
    <p><label>Password<br><input type="password" name="password" required style="width:100%;padding:0.5rem;"></label></p>
    <p><button type="submit">Sign in</button></p>
  </form>
</body>
</html>
`;

export function registerAdminAuthRoutes(app: Express) {
  // POST /api/login: JSON-only login for SPA (admin now; future: DB users). Always registered.
  app.post("/api/login", async (req: Request, res: Response) => {
    const contentType = (req.headers["content-type"] || "").toLowerCase();
    if (!contentType.includes("application/json")) {
      res.status(400).json({ success: false, error: "Use JSON." });
      return;
    }
    const body = req.body as { email?: string; password?: string };
    const email = (body?.email ?? "").trim();
    const password = body?.password ?? "";

    if (!ENV.adminEmail || !ENV.adminPassword) {
      res.status(503).json({ success: false, error: "Login not configured." });
      return;
    }
    if (!process.env.DATABASE_URL) {
      res.status(503).json({ success: false, error: "Database not configured." });
      return;
    }
    if (email !== ENV.adminEmail || password !== ENV.adminPassword) {
      res.status(401).json({ success: false, error: "Invalid email or password." });
      return;
    }
    try {
      const openId = `admin:${email}`;
      await db.upsertUser({
        openId,
        name: "Admin",
        email,
        loginMethod: "admin",
        role: "admin",
        lastSignedIn: new Date(),
      });
      const sessionToken = await sdk.createSessionToken(openId, {
        name: "Admin",
        expiresInMs: ONE_YEAR_MS,
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      res.json({ success: true });
    } catch (error) {
      console.error("[Login] failed", error);
      res.status(500).json({ success: false, error: "Login failed." });
    }
  });

  if (!ENV.adminEmail || !ENV.adminPassword) return;

  app.get("/api/admin-login", (_req: Request, res: Response) => {
    res.type("html").send(ADMIN_LOGIN_HTML);
  });

  app.post("/api/admin-login", async (req: Request, res: Response) => {
    if (!process.env.DATABASE_URL) {
      res.status(503).type("html").send("<p>Database not configured.</p>");
      return;
    }

    let email = "";
    let password = "";

    const contentType = (req.headers["content-type"] || "").toLowerCase();
    if (contentType.includes("application/json")) {
      try {
        const body = req.body as { email?: string; password?: string };
        email = (body.email ?? "").trim();
        password = body.password ?? "";
      } catch {
        res.status(400).type("html").send("<p>Invalid JSON.</p>");
        return;
      }
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      email = (req.body?.email ?? "").trim();
      password = req.body?.password ?? "";
    } else {
      res.status(400).type("html").send("<p>Use JSON or form.</p>");
      return;
    }

    if (
      email !== ENV.adminEmail ||
      password !== ENV.adminPassword
    ) {
      res.status(401).type("html").send("<p>Invalid email or password.</p>");
      return;
    }

    try {
      const openId = `admin:${email}`;
      await db.upsertUser({
        openId,
        name: "Admin",
        email,
        loginMethod: "admin",
        role: "admin",
        lastSignedIn: new Date(),
      });

      const sessionToken = await sdk.createSessionToken(openId, {
        name: "Admin",
        expiresInMs: ONE_YEAR_MS,
      });

      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      const redirectUrl = `${req.protocol}://${req.get("host") ?? "localhost:3000"}/`;
      res.redirect(302, redirectUrl);
    } catch (error) {
      console.error("[Admin Auth] Login failed", error);
      res.status(500).type("html").send("<p>Login failed.</p>");
    }
  });
}
