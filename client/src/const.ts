export { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";

/** Whether dev login is available (DEV_BYPASS_AUTH + development mode, or when OAuth not configured) */
export const isDevLoginEnabled = (): boolean => {
  try {
    if (import.meta.env.DEV !== true) return false;
    if (import.meta.env.VITE_DEV_LOGIN === "true") return true;
    const url = import.meta.env.VITE_OAUTH_PORTAL_URL;
    return !url || (typeof url === "string" && url.trim() === "");
  } catch {
    return true;
  }
};

const DEV_LOGIN_PATH = "/api/dev-login";

// Generate login URL at runtime so redirect URI reflects the current origin.
// Never throws — always returns a valid path.
export const getLoginUrl = (): string => {
  try {
    if (isDevLoginEnabled()) return DEV_LOGIN_PATH;

    const oauthPortalUrl = import.meta.env.VITE_OAUTH_PORTAL_URL;
    const appId = import.meta.env.VITE_APP_ID;

    if (!oauthPortalUrl || !appId || typeof oauthPortalUrl !== "string" || typeof appId !== "string") {
      return DEV_LOGIN_PATH;
    }

    const redirectUri = `${typeof window !== "undefined" ? window.location.origin : ""}/api/oauth/callback`;
    const state = btoa(redirectUri);
    const url = new URL(`${oauthPortalUrl}/app-auth`);
    url.searchParams.set("appId", appId);
    url.searchParams.set("redirectUri", redirectUri);
    url.searchParams.set("state", state);
    url.searchParams.set("type", "signIn");
    return url.toString();
  } catch {
    return DEV_LOGIN_PATH;
  }
};
