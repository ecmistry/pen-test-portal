/**
 * Bring-your-own OIDC SSO (Okta / Azure AD / Keycloak / Auth0).
 * Env:
 *   OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI
 *   OIDC_SCOPES (default openid profile email)
 */
import { createHash, randomBytes } from "crypto";
import type { Express, Request, Response } from "express";
import * as db from "../db";
import { COOKIE_NAME, SESSION_TTL_MS } from "@shared/const";
import { getSessionCookieOptions } from "./cookies";
import { sdk } from "./sdk";

type OidcDiscovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
};

let discoveryCache: OidcDiscovery | null = null;

function oidcEnabled() {
  return !!(process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET);
}

async function discover(): Promise<OidcDiscovery> {
  if (discoveryCache) return discoveryCache;
  const issuer = process.env.OIDC_ISSUER!.replace(/\/$/, "");
  const res = await fetch(`${issuer}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  discoveryCache = (await res.json()) as OidcDiscovery;
  return discoveryCache;
}

function b64url(buf: Buffer) {
  return buf.toString("base64url");
}

function readCookie(req: Request, name: string): string | undefined {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

export function registerOidcRoutes(app: Express) {
  app.get("/api/oidc/enabled", (_req, res) => {
    res.json({ enabled: oidcEnabled(), issuer: process.env.OIDC_ISSUER || null });
  });

  app.get("/api/oidc/login", async (req: Request, res: Response) => {
    if (!oidcEnabled()) {
      res.status(404).json({ error: "OIDC not configured" });
      return;
    }
    try {
      const d = await discover();
      const state = b64url(randomBytes(24));
      const verifier = b64url(randomBytes(32));
      const challenge = b64url(createHash("sha256").update(verifier).digest());
      const cookieOpts = getSessionCookieOptions(req);
      res.cookie("oidc_state", state, { ...cookieOpts, maxAge: 600_000, httpOnly: true });
      res.cookie("oidc_verifier", verifier, { ...cookieOpts, maxAge: 600_000, httpOnly: true });

      const redirectUri = process.env.OIDC_REDIRECT_URI || `${req.protocol}://${req.get("host")}/api/oidc/callback`;
      const scopes = process.env.OIDC_SCOPES || "openid profile email";
      const url = new URL(d.authorization_endpoint);
      url.searchParams.set("client_id", process.env.OIDC_CLIENT_ID!);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", scopes);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("state", state);
      url.searchParams.set("code_challenge", challenge);
      url.searchParams.set("code_challenge_method", "S256");
      res.redirect(302, url.toString());
    } catch (err) {
      console.error("[OIDC] login failed", err);
      res.status(500).json({ error: "OIDC login failed" });
    }
  });

  app.get("/api/oidc/callback", async (req: Request, res: Response) => {
    if (!oidcEnabled()) {
      res.status(404).json({ error: "OIDC not configured" });
      return;
    }
    try {
      const code = typeof req.query.code === "string" ? req.query.code : "";
      const state = typeof req.query.state === "string" ? req.query.state : "";
      const savedState = readCookie(req, "oidc_state");
      const verifier = readCookie(req, "oidc_verifier");
      if (!code || !state || !savedState || state !== savedState || !verifier) {
        res.status(400).json({ error: "Invalid OIDC state" });
        return;
      }
      const d = await discover();
      const redirectUri = process.env.OIDC_REDIRECT_URI || `${req.protocol}://${req.get("host")}/api/oidc/callback`;
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: process.env.OIDC_CLIENT_ID!,
        client_secret: process.env.OIDC_CLIENT_SECRET!,
        code_verifier: verifier,
      });
      const tokenRes = await fetch(d.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
        signal: AbortSignal.timeout(15000),
      });
      if (!tokenRes.ok) {
        res.status(401).json({ error: "OIDC token exchange failed" });
        return;
      }
      const tokens = (await tokenRes.json()) as { access_token: string };
      const uiRes = await fetch(d.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
        signal: AbortSignal.timeout(10000),
      });
      if (!uiRes.ok) {
        res.status(401).json({ error: "OIDC userinfo failed" });
        return;
      }
      const info = (await uiRes.json()) as { sub: string; email?: string; name?: string; preferred_username?: string };
      const openId = `oidc:${info.sub}`;
      await db.upsertUser({
        openId,
        name: info.name || info.preferred_username || null,
        email: info.email ?? null,
        loginMethod: "oidc",
        lastSignedIn: new Date(),
      });
      const sessionToken = await sdk.createSessionToken(openId, {
        name: info.name || info.preferred_username || "",
        expiresInMs: SESSION_TTL_MS,
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.clearCookie("oidc_state", cookieOptions);
      res.clearCookie("oidc_verifier", cookieOptions);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: SESSION_TTL_MS });
      res.redirect(302, "/dashboard");
    } catch (err) {
      console.error("[OIDC] callback failed", err);
      res.status(500).json({ error: "OIDC callback failed" });
    }
  });
}
