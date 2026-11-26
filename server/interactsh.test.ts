import { createCipheriv, randomBytes } from "crypto";
import { describe, expect, it } from "vitest";
import { decryptInteractshPayloads } from "./interactsh";

describe("decryptInteractshPayloads", () => {
  it("decrypts AES-128-CFB blobs with IV prefix", () => {
    const key = randomBytes(16);
    const iv = randomBytes(16);
    const plain = Buffer.from('{"full-id":"gs123probe.oast.pro","protocol":"dns"}');
    const cipher = createCipheriv("aes-128-cfb", key, iv);
    const enc = Buffer.concat([iv, cipher.update(plain), cipher.final()]);
    const out = decryptInteractshPayloads(key, [enc.toString("base64")]);
    expect(out.join("")).toContain("gs123probe");
  });
});
