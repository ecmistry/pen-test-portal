import { describe, expect, it, vi } from "vitest";

const mockUser = {
  id: 1,
  openId: "user-1",
  email: "u@test.com",
  name: "User",
  loginMethod: "oauth" as const,
  role: "user" as const,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

vi.mock("./sdk", () => ({
  sdk: {
    authenticateRequest: vi.fn(),
  },
}));

import { createContext } from "./context";
import { sdk } from "./sdk";

describe("createContext", () => {
  it("returns user when sdk.authenticateRequest resolves", async () => {
    vi.mocked(sdk.authenticateRequest).mockResolvedValueOnce(mockUser);
    const req = {} as any;
    const res = {} as any;
    const result = await createContext({ req, res });
    expect(result.user).toEqual(mockUser);
    expect(result.req).toBe(req);
    expect(result.res).toBe(res);
  });

  it("returns null user when sdk.authenticateRequest rejects", async () => {
    vi.mocked(sdk.authenticateRequest).mockRejectedValueOnce(new Error("Unauthorized"));
    const req = {} as any;
    const res = {} as any;
    const result = await createContext({ req, res });
    expect(result.user).toBeNull();
  });
});
