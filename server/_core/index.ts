import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import * as db from "../db";
import { registerAdminAuthRoutes } from "./adminAuth";
import { registerDevAuthRoutes } from "./devAuth";
import { registerOAuthRoutes } from "./oauth";
import { applySecurityMiddleware, assertSecureConfig } from "./security";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

async function startServer() {
  assertSecureConfig();

  // Mark any scans left "running" or "queued" by a previous process as failed (e.g. after restart/crash)
  await db.failStaleScansOnStartup().catch((err) => console.warn("[Startup] failStaleScansOnStartup:", err.message));

  const app = express();
  const server = createServer(app);
  applySecurityMiddleware(app);
  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ limit: "100kb", extended: false }));
  registerOAuthRoutes(app);
  registerDevAuthRoutes(app);
  registerAdminAuthRoutes(app);

  // SSE live scan logs: GET /api/scans/:id/logs/stream?afterId=0
  app.get("/api/scans/:id/logs/stream", async (req, res) => {
    try {
      const scanId = Number(req.params.id);
      if (!Number.isFinite(scanId)) {
        res.status(400).end("bad scan id");
        return;
      }
      const ctx = await createContext({ req, res } as any);
      if (!ctx.user) {
        res.status(401).end("unauthorized");
        return;
      }
      const scan = await db.getScanById(scanId);
      if (!scan) {
        res.status(404).end("not found");
        return;
      }
      if (ctx.user.role !== "admin" && scan.userId !== ctx.user.id) {
        res.status(403).end("forbidden");
        return;
      }

      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.flushHeaders?.();

      let afterId = Number(req.query.afterId || 0) || 0;
      let closed = false;
      req.on("close", () => { closed = true; });

      const tick = async () => {
        while (!closed) {
          const logs = await db.getLogsAfterId(scanId, afterId);
          for (const row of logs) {
            afterId = row.id;
            res.write(`data: ${JSON.stringify(row)}\n\n`);
          }
          const latest = await db.getScanById(scanId);
          if (latest && (latest.status === "completed" || latest.status === "failed" || latest.status === "cancelled")) {
            res.write(`event: done\ndata: ${JSON.stringify({ status: latest.status })}\n\n`);
            res.end();
            return;
          }
          await new Promise((r) => setTimeout(r, 1000));
        }
      };
      tick().catch(() => { try { res.end(); } catch { /* ignore */ } });
    } catch {
      res.status(500).end("error");
    }
  });

  // tRPC API
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
    })
  );
  // development mode uses Vite, production mode uses static files
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);

  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
    // Start schedule runner after listen so DB/light migrations are ready
    import("../scheduleRunner")
      .then(({ startScheduleRunner }) => startScheduleRunner(60_000))
      .catch((err) => console.warn("[Startup] schedule runner failed to start:", err?.message || err));
  });
}

startServer().catch(err => {
  console.error(err);
  process.exit(1);
});
