import fs from "fs/promises";
import path from "path";
import { describe, expect, it } from "vitest";

const projectRoot = path.resolve(import.meta.dirname, "..");
const methodologyPath = path.join(projectRoot, "docs", "PENTEST_METHODOLOGY.md");

describe("methodology document (docs/PENTEST_METHODOLOGY.md)", () => {
  it("references ghoststrike.tech in footer", async () => {
    const content = await fs.readFile(methodologyPath, "utf-8");
    expect(content).toContain("ghoststrike.tech");
  });
});
