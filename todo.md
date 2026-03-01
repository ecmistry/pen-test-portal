# PenTest Portal — TODO

## Phase 2: Database Schema & Migrations
- [ ] Define targets table (url, name, description, scan frequency, owner)
- [ ] Define scans table (target_id, status, tool, started_at, completed_at, score)
- [ ] Define scan_results table (scan_id, category, severity, title, description, recommendation)
- [ ] Define scan_logs table (scan_id, timestamp, level, message)
- [ ] Define schedules table (target_id, cron_expression, enabled, last_run, next_run)
- [ ] Define reports table (scan_id, format, content, generated_at)
- [ ] Run migrations via webdev_execute_sql

## Phase 3: Backend
- [ ] Scan engine: Node.js child_process runner for ZAP/Nikto/Nuclei/custom bash
- [ ] Scan scheduler: cron-based job runner with per-target schedules
- [ ] tRPC router: targets CRUD (list, create, update, delete)
- [ ] tRPC router: scans (start, cancel, status, history)
- [ ] tRPC router: scan results and findings
- [ ] tRPC router: reports (generate, list, get, export)
- [ ] tRPC router: admin (users list, promote/demote, global stats)
- [ ] tRPC router: schedules (create, update, delete, toggle)
- [ ] Real-time scan log streaming via SSE or polling
- [ ] Report generation: executive summary, findings, risk score, recommendations
- [ ] PDF export using markdown-to-PDF pipeline
- [ ] JSON export of scan results
- [ ] Markdown export of full report

## Phase 4: Frontend
- [ ] Dark-themed security ops dashboard layout (DashboardLayout)
- [ ] Landing/login page with security branding
- [ ] Dashboard home: stats cards, recent scans, risk score trend chart
- [ ] Target management page: list, add, edit, delete targets
- [ ] Scan launch page: select target, tools, run now or schedule
- [ ] Real-time scan progress page: live log stream, progress bar, status
- [ ] Scan history page: paginated list with filters
- [ ] Report viewer page: rendered markdown report with severity badges
- [ ] Vulnerability findings page: filterable table by severity/category
- [ ] Trends/analytics page: recharts graphs for vulnerability trends

## Phase 5: Admin & Export
- [ ] Admin panel: user list with role management
- [ ] Admin panel: global scan statistics
- [ ] Admin panel: system configuration (default tools, scan limits)
- [ ] Report export: PDF download
- [ ] Report export: Markdown download
- [ ] Report export: JSON download
- [ ] Compliance-ready report formatting (OWASP, PTES, NIST references)

## Phase 6: Tests & Polish
- [ ] Vitest: targets router tests
- [ ] Vitest: scans router tests
- [ ] Vitest: report generation tests
- [ ] Final UI polish and responsive design
- [ ] Save checkpoint and deliver
