# PenTest Portal

Automated penetration testing platform with OWASP Top 10 coverage, scheduled scans, and compliance-ready reports.

## Quick Start (Local Development)

### 1. Install dependencies

```bash
pnpm install
```

### 2. Start MySQL (Docker)

```bash
docker compose up -d
```

### 3. Run database migrations

```bash
pnpm db:migrate
```

### 4. Start the dev server

```bash
pnpm dev
```

The portal runs at **http://localhost:3000/**.

### 5. Sign in (Dev mode)

With `DEV_BYPASS_AUTH=true` and `VITE_DEV_LOGIN=true` in `.env`, use **Dev Login** to sign in without OAuth. This creates an admin user for local testing.

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | Session signing secret |
| `DATABASE_URL` | Yes* | MySQL connection string (e.g. `mysql://pentest:pentest@localhost:3306/pentest_portal`) |
| `DEV_BYPASS_AUTH` | No | Set `true` for dev login without OAuth |
| `VITE_DEV_LOGIN` | No | Set `true` to show Dev Login button (with `DEV_BYPASS_AUTH`) |
| `VITE_APP_ID` | Prod | App ID for OAuth |
| `OAUTH_SERVER_URL` | Prod | OAuth server URL |
| `VITE_OAUTH_PORTAL_URL` | Prod | OAuth portal URL |

\* Required for full functionality (targets, scans, reports). Landing page works without DB.

## Scripts

- `pnpm dev` — Start dev server with Vite HMR
- `pnpm build` — Build for production
- `pnpm start` — Run production server
- `pnpm db:migrate` — Run database migrations
- `pnpm db:push` — Generate migrations and run them
- `pnpm test` — Run test suite (Vitest)

## Testing

The project uses [Vitest](https://vitest.dev/) for unit and integration-style tests. Run all tests with:

```bash
pnpm test
```

### Test coverage

| Area | Location | Description |
|------|----------|-------------|
| **Auth** | `server/auth.logout.test.ts`, `server/_core/adminAuth.test.ts` | Logout (tRPC), POST /api/login (invalid/valid credentials, JSON-only) |
| **Scan engine** | `server/scanEngine.test.ts` | `calculateScore`, `isSpaFallback`, `hasFileSpecificContent` |
| **tRPC routers** | `server/routers.test.ts` | `auth.me`, `targets.list`, `targets.get`, `scans.get`, `scans.list` (with mocked db) |
| **Database** | `server/db.test.ts` | `getDb` when `DATABASE_URL` is unset |
| **Reports** | `server/reportGenerator.test.ts` | `generateMarkdownReport`, `generateExecutiveSummary`, `generateJSONReport` |

Client tests (React components) can be added under `client/src/**/*.test.tsx`; the Vitest config is set up to run them with a jsdom environment.

**Coverage:** Run `pnpm test --coverage`. Coverage is reported for the testable server surface; bootstrap and integration-heavy modules (e.g. `db`, `scanEngine`, `sdk`, `oauth`, `index`, `vite`) are excluded so the percentage reflects unit-testable code.

## Tech Stack

- **Frontend:** React 19, Vite, Tailwind, tRPC
- **Backend:** Express, tRPC, Drizzle ORM
- **Database:** MySQL 8
- **Auth:** OAuth (or dev bypass for local)
