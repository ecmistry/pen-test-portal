import { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";
import type { Express, Request, Response } from "express";
import * as db from "../db";
import { getSessionCookieOptions } from "./cookies";
import { ENV } from "./env";
import { sdk } from "./sdk";

const DEV_OPEN_ID = "dev-user-local";

export function registerDevAuthRoutes(app: Express) {
  if (!ENV.devBypassAuth) return;

  app.get("/api/dev-login", async (req: Request, res: Response) => {
    if (!process.env.DATABASE_URL) {
      res.status(503).json({
        error: "Dev login requires DATABASE_URL. Start MySQL and run migrations.",
      });
      return;
    }

    try {
      await db.upsertUser({
        openId: DEV_OPEN_ID,
        name: "Dev User",
        email: "dev@localhost",
        loginMethod: "dev",
        role: "admin",
        lastSignedIn: new Date(),
      });

      const sessionToken = await sdk.createSessionToken(DEV_OPEN_ID, {
        name: "Dev User",
        expiresInMs: ONE_YEAR_MS,
      });

      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      const redirectUrl = `${req.protocol}://${req.get("host") ?? "localhost:3000"}/`;
      res.redirect(302, redirectUrl);
    } catch (error) {
      console.error("[Dev Auth] Login failed", error);
      res.status(500).json({ error: "Dev login failed" });
    }
  });
}
