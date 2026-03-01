export const ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl:
    process.env.BUILT_IN_FORGE_API_URL ??
    (process.env.GEMINI_API_KEY
      ? "https://generativelanguage.googleapis.com/v1beta/openai"
      : ""),
  forgeApiKey:
    process.env.BUILT_IN_FORGE_API_KEY ?? process.env.GEMINI_API_KEY ?? "",
  devBypassAuth: process.env.DEV_BYPASS_AUTH === "true",
  adminEmail: process.env.ADMIN_EMAIL ?? "",
  adminPassword: process.env.ADMIN_PASSWORD ?? "",
};
