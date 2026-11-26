import { timingSafeEqual, createHash } from "crypto";
import type { Express } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { ENV } from "./env";

const MIN_JWT_SECRET_LENGTH = 32;

export function assertSecureConfig() {
  if (!ENV.isProduction) return;
  if (ENV.cookieSecret.length < MIN_JWT_SECRET_LENGTH) {
    throw new Error(
      `JWT_SECRET must be at least ${MIN_JWT_SECRET_LENGTH} characters in production (generate with: openssl rand -hex 32)`
    );
  }
  if (ENV.devBypassAuth) {
    throw new Error("DEV_BYPASS_AUTH must not be enabled in production");
  }
}

export function safeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

export function applySecurityMiddleware(app: Express) {
  app.disable("x-powered-by");
  // nginx on the same host terminates TLS and sets X-Forwarded-*
  app.set("trust proxy", "loopback");

  app.use(
    helmet({
      contentSecurityPolicy: ENV.isProduction
        ? {
            directives: {
              defaultSrc: ["'self'"],
              scriptSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              imgSrc: ["'self'", "data:", "blob:"],
              fontSrc: ["'self'", "data:"],
              connectSrc: ["'self'"],
              objectSrc: ["'none'"],
              frameAncestors: ["'none'"],
              baseUri: ["'self'"],
              formAction: ["'self'"],
            },
          }
        : false,
      strictTransportSecurity: ENV.isProduction
        ? { maxAge: 31536000, includeSubDomains: true }
        : false,
    })
  );

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: { success: false, error: "Too many login attempts. Try again later." },
  });
  app.use(["/api/login", "/api/admin-login", "/api/dev-login"], loginLimiter);

  const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 600,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  });
  app.use("/api", apiLimiter);
}
