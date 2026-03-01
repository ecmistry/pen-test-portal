import fs from "fs/promises";
import path from "path";
import { z } from "zod";
import { notifyOwner } from "./notification";
import { adminProcedure, publicProcedure, router } from "./trpc";

const METHODOLOGY_FALLBACK = `# Penetration Testing Methodology\n\nMethodology document not found. See the repository \`docs/PENTEST_METHODOLOGY.md\` or contact your administrator.`;

export const systemRouter = router({
  getMethodology: publicProcedure.query(async () => {
    try {
      const docPath = path.join(process.cwd(), "docs", "PENTEST_METHODOLOGY.md");
      const content = await fs.readFile(docPath, "utf-8");
      return content;
    } catch {
      return METHODOLOGY_FALLBACK;
    }
  }),

  health: publicProcedure
    .input(
      z.object({
        timestamp: z.number().min(0, "timestamp cannot be negative"),
      })
    )
    .query(() => ({
      ok: true,
    })),

  notifyOwner: adminProcedure
    .input(
      z.object({
        title: z.string().min(1, "title is required"),
        content: z.string().min(1, "content is required"),
      })
    )
    .mutation(async ({ input }) => {
      const delivered = await notifyOwner(input);
      return {
        success: delivered,
      } as const;
    }),
});
