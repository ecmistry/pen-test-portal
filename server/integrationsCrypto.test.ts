import { describe, expect, it } from "vitest";
import { encryptIntegrationsConfig, decryptIntegrationsConfig, redactIntegrationsConfig } from "./integrationsCrypto";
import type { IntegrationsConfig } from "./ticketingIntegration";

describe("redactIntegrationsConfig", () => {
  it("masks webhook secrets along with other tokens", () => {
    const config: IntegrationsConfig = {
      webhooks: [
        { url: "https://hooks.example.com/x", secret: "super-secret-signing-key", events: ["scan.completed"] },
      ],
      jira: { enabled: true, baseUrl: "https://jira.example.com", email: "a@b.c", apiToken: "jira-token", projectKey: "SEC" },
      github: { enabled: true, token: "ghp_xxx", owner: "o", repo: "r" },
      linear: { enabled: true, apiKey: "lin_xxx", teamId: "t" },
      repoScan: { githubToken: "ghp_clone" },
    };
    const redacted = redactIntegrationsConfig(config);
    expect(redacted.webhooks?.[0]?.secret).toBe("********");
    expect(redacted.jira?.apiToken).toBe("********");
    expect(redacted.github?.token).toBe("********");
    expect(redacted.linear?.apiKey).toBe("********");
    expect(redacted.repoScan?.githubToken).toBe("********");
    // original unchanged
    expect(config.webhooks?.[0]?.secret).toBe("super-secret-signing-key");
  });

  it("round-trips encrypt/decrypt", () => {
    process.env.JWT_SECRET = "test-secret-for-crypto-unit";
    const config: IntegrationsConfig = {
      webhooks: [{ url: "https://hooks.example.com/y", secret: "abc", events: ["scan.failed"] }],
    };
    const enc = encryptIntegrationsConfig(config);
    const dec = decryptIntegrationsConfig(enc);
    expect(dec.webhooks?.[0]?.secret).toBe("abc");
  });
});
