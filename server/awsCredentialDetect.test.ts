import { afterEach, describe, expect, it } from "vitest";
import {
  awsCredentialsRemediation,
  describeAwsKeyExposure,
  extractAwsKeyHits,
  getCanaryAwsKeyPrefixes,
  isConfiguredCanaryKey,
  looksLikeAwsCredentialsFile,
  maskAwsAccessKeyId,
} from "./awsCredentialDetect";

describe("awsCredentialDetect", () => {
  afterEach(() => {
    delete process.env.CANARY_AWS_KEY_PREFIXES;
  });

  it("masks access key IDs", () => {
    expect(maskAwsAccessKeyId("AKIAIOSFODNN7EXAMPLE")).toBe("AKIA****MPLE");
  });

  it("extracts AKIA and ASIA keys from body text", () => {
    const body = `leak AKIAIOSFODNN7EXAMPLE and ASIAIOSFODNN7EXAMPLF temporary`;
    const hits = extractAwsKeyHits(body, []);
    expect(hits.map((h) => h.accessKeyId).sort()).toEqual([
      "AKIAIOSFODNN7EXAMPLE",
      "ASIAIOSFODNN7EXAMPLF",
    ].sort());
    expect(hits.find((h) => h.accessKeyId.startsWith("ASIA"))?.isTemporary).toBe(true);
  });

  it("extracts named profile context", () => {
    const body = `[backup-prod]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n`;
    expect(looksLikeAwsCredentialsFile(body)).toBe(true);
    const hits = extractAwsKeyHits(body, []);
    expect(hits).toHaveLength(1);
    expect(hits[0].profileName).toBe("backup-prod");
    expect(hits[0].maskedAccessKeyId).toContain("****");
  });

  it("tags configured canary prefixes", () => {
    process.env.CANARY_AWS_KEY_PREFIXES = "AKIAIOSF,ASIATEST";
    expect(getCanaryAwsKeyPrefixes()).toEqual(["AKIAIOSF", "ASIATEST"]);
    expect(isConfiguredCanaryKey("AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(isConfiguredCanaryKey("AKIAOTHERKEY0000000")).toBe(false);

    const hits = extractAwsKeyHits("key=AKIAIOSFODNN7EXAMPLE");
    expect(hits[0].isHoneytoken).toBe(true);
    expect(describeAwsKeyExposure(hits[0]).evidenceExtra).toContain("honeytoken=true");
    expect(awsCredentialsRemediation(true)).toMatch(/honeytoken|compromised/i);
  });

  it("rejects HTML as credentials file", () => {
    expect(looksLikeAwsCredentialsFile("<!DOCTYPE html><html>AKIAIOSFODNN7EXAMPLE</html>")).toBe(false);
  });
});
