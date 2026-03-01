# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Login page** (`/login`): Dedicated login page with Ghoststrike logo, email/password form for admin and future customers. Sign-in and Get Started links now route to `/login`.
- **POST /api/login**: JSON-only login endpoint for the SPA; validates credentials, sets session cookie, returns `{ success: true }` or error. Supports admin credentials from env; extensible for future DB-backed users.
- **Scan “still working” indicator**: When a scan is running, a prominent blue banner shows “Scan in progress” with a spinner and explains that steps like Nikto, Nuclei, and ZAP can take 2–5 minutes with no new log lines. Scan Output header shows “· updating every 2s” while polling.

### Changed

- **Home hero logo**: Increased size from `h-14` to `h-32` (128px) for better visibility.
- **Vite dev server**: Added `52.56.193.19`, `galaxy-api.tech`, and `www.galaxy-api.tech` to `allowedHosts` so the app can be accessed by IP or domain during development.
- **Deploy docs**: Documented current server public IP (52.56.193.19) in `deploy/README.md` DNS section.
- **Auth redirects**: All sign-in entry points (Home, Methodology, AppLayout, DashboardLayout, main.tsx, useAuth default) now redirect to `/login` instead of OAuth/dev URL.
- **Nikto in scan engine**: Scan engine now resolves Nikto via `which nikto`, then `/usr/local/bin/nikto`, then `/usr/bin/nikto`, so full scans find Nikto even when systemd does not have `/usr/local/bin` in PATH. Updated “not installed” message to point to GitHub install instructions.

### Fixed

- **Home page crash**: Added missing `Shield` icon import from `lucide-react` in `Home.tsx` (was used in features list but not imported).
