# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **10 new scan tools**: AI prompt injection (PEN-27), secret/credential exposure (PEN-33), URL normalisation bypass (PEN-42), insecure HTTP client config (PEN-52), JWT security, cookie security flags, HTTP request smuggling, CRLF injection, open redirect, prototype pollution. Full-mode scans now run 28 built-in tools.
- **Authenticated vs unauthenticated scan differentiation**: Scans track authentication mode, tag findings as pre-auth/post-auth, and reports include auth-mode banner, coverage depth table, tool auth capability matrix, and cross-mode trend warnings.
- **Methodology & compliance docs**: `PENTEST_METHODOLOGY.md` updated with sections 4.13–4.22 for new tools, section 5 for auth-mode scanning. `COMPLIANCE_STANDARDS.md` expanded to 37 CWE IDs, updated OWASP/ATT&CK/PTES/ISO 27001 tables, 24 built-in modules documented.
- **OWASP ZAP integration**: ZAP quick scan with JSON output parsing — individual alerts extracted with severity, CWE, and remediation. Stale lock file cleanup and per-scan output files for concurrency.

### Changed

- **False positive reduction — debug endpoints**: Debug/diagnostic endpoint checks (`/debug`, `/actuator`, `/metrics`, etc.) now compare responses against the SPA baseline. SPA fallback responses (same HTML shell as `/`) are suppressed instead of reported as medium-severity findings.
- **False positive reduction — Nikto legacy CGI**: Legacy CGI/ASP/IIS/FrontPage probes (cart32.exe, classified.cgi, _vti_bin, etc.) are grouped into a single informational summary instead of individual medium-severity findings.
- **False positive reduction — sensitive file detection**: `hasFileSpecificContent()` expanded to cover `.git/HEAD`, `.sql` dumps, `.json`/`.yml` configs, `.htaccess`, `.npmrc`, `docker-compose`, `web.config` — validates actual file content vs SPA HTML shell.
- **Brute force finding transparency**: "No brute force protection detected" now includes the exact tested endpoint path and method (e.g. "Tested: POST /api/trpc/auth.login"), notes whether the endpoint was discovered or a fallback, and warns about possible false positives when a non-login path was tested.
- **Login endpoint discovery**: Added `/api/v1/auth/login`, `/api/v1/login`, `/api/session`, `/api/auth/signin`, and GraphQL `mutation { login }` to the auto-discovery list.
- **Account enumeration evidence**: Finding now includes which endpoint was tested.

### Fixed

- **Report generation 500 error**: Upgraded `markdownContent`, `executiveSummary`, and `complianceNotes` columns from MySQL `TEXT` (64KB) to `MEDIUMTEXT` (16MB). Reports with 24+ scan tools were exceeding the column size limit.

---

## [Previous]

### Added

- **PDF report export**: Reports can be exported as PDF in addition to Markdown and JSON. PDF is generated on demand (jsPDF + jspdf-autotable) with the same structure as the Markdown report (Scope, Executive Summary, Findings Summary, Detailed Findings, Recommendations, Standards, Appendix). Download PDF button on the report view.
- **Commercial-style report structure**: Reports now include Scope of Work (in/out of scope), Executive Summary with business-risk narrative and severity distribution bar, Findings Summary table (#, Title, Severity, Category, Status), per-finding Impact text, full evidence (up to 3000 chars), numbered sections 1–8, and Appendix A (Glossary). JSON report includes `scope` and per-finding `impact`.
- **Methodology doc updates**: New section 7 (Reports & export formats) describing report structure and PDF/Markdown/JSON exports; section 4.9 (Nikto) updated to note non-zero exit handling and output capture; sections 8–9 (Limitations, References); footer link to ghoststrike.tech/methodology.
- **Login page** (`/login`): Dedicated login page with Ghoststrike logo, email/password form for admin and future customers. Sign-in and Get Started links now route to `/login`.
- **POST /api/login**: JSON-only login endpoint for the SPA; validates credentials, sets session cookie, returns `{ success: true }` or error. Supports admin credentials from env; extensible for future DB-backed users.
- **Scan “still working” indicator**: When a scan is running, a prominent blue banner shows “Scan in progress” with a spinner and explains that steps like Nikto, Nuclei, and ZAP can take 2–5 minutes with no new log lines. Scan Output header shows “· updating every 2s” while polling.
- **PDF report tests** (`server/pdfReport.test.ts`): Unit tests for PDF generation (buffer output, valid PDF header, target name, empty findings).

### Changed

- **Home hero logo**: Increased size from `h-14` to `h-32` (128px) for better visibility.
- **Vite dev server**: Added `52.56.193.19`, `ghoststrike.tech`, and `www.ghoststrike.tech` to `allowedHosts` so the app can be accessed by IP or domain during development.
- **Deploy docs**: Documented current server public IP (52.56.193.19) in `deploy/README.md` DNS section.
- **Auth redirects**: All sign-in entry points (Home, Methodology, AppLayout, DashboardLayout, main.tsx, useAuth default) now redirect to `/login` instead of OAuth/dev URL.
- **Nikto in scan engine**: Scan engine now resolves Nikto via `which nikto`, then `/usr/local/bin/nikto`, then `/usr/bin/nikto`, so full scans find Nikto even when systemd does not have `/usr/local/bin` in PATH. Updated “not installed” message to point to GitHub install instructions.
- **Nikto non-zero exit handling**: Nikto is run via `execCapture` so stdout/stderr are always captured regardless of exit code; no more “Command failed: …” in logs when Nikto finds issues. Friendlier error message in outer catch for real failures.

### Fixed

- **Home page crash**: Added missing `Shield` icon import from `lucide-react` in `Home.tsx` (was used in features list but not imported).
- **scanEngine execCapture**: Use `String(stdout ?? "")` / `String(stderr ?? "")` to satisfy TypeScript when resolving exec callback output.
