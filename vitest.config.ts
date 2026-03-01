import { defineConfig } from "vitest/config";
import path from "path";

const templateRoot = path.resolve(import.meta.dirname);

export default defineConfig({
  root: templateRoot,
  resolve: {
    alias: {
      "@": path.resolve(templateRoot, "client", "src"),
      "@shared": path.resolve(templateRoot, "shared"),
      "@assets": path.resolve(templateRoot, "attached_assets"),
    },
  },
  test: {
    environment: "node",
    include: [
      "server/**/*.test.ts",
      "server/**/*.spec.ts",
      "client/src/**/*.test.ts",
      "client/src/**/*.spec.ts",
      "client/src/**/*.test.tsx",
      "client/src/**/*.spec.tsx",
    ],
    environmentMatchGlobs: [["client/**", "jsdom"]],
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary", "json-summary"],
      include: ["server/**/*.ts"],
      // Exclude tests, types, bootstrap, and integration-heavy modules (db, scanEngine, sdk, oauth, etc.)
      exclude: [
        "server/**/*.test.ts",
        "server/**/*.spec.ts",
        "**/node_modules/**",
        "drizzle/**",
        "**/*.d.ts",
        "server/_core/index.ts",
        "server/_core/vite.ts",
        "server/db.ts",
        "server/scanEngine.ts",
        "server/storage.ts",
        "server/_core/sdk.ts",
        "server/_core/oauth.ts",
        "server/_core/dataApi.ts",
        "server/_core/llm.ts",
        "server/_core/map.ts",
        "server/_core/transcription.ts",
        "server/_core/imageGeneration.ts",
        "server/_core/voiceTranscription.ts",
        "server/_core/types/authTypes.ts",
      ],
    },
  },
});
