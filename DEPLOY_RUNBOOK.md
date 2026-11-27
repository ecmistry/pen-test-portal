# Ghoststrike — rebuild, redeploy & health runbook

Repeatable production procedure for the EC2 host that serves **ghoststrike.tech**.
Use this every time you ship code so the steps stay consistent and known weaknesses stay visible.

**Host paths**
- App: `/home/ec2-user/pen-test-portal`
- Service: `pentest-portal.service` → `node dist/index.js`
- MySQL: Docker Compose service `mysql` (localhost:3306)
- Edge: Nginx → `127.0.0.1:3000` (HTTPS on `ghoststrike.tech`)

---

## 1. Pre-flight (before rebuild)

```bash
cd /home/ec2-user/pen-test-portal

# Confirm branch + commit you intend to ship
git status -sb
git log -1 --oneline

# Do not commit .env. Confirm it is ignored.
git check-ignore -v .env

# Optional: unit tests before spending build time
pnpm test
```

If there are uncommitted changes you mean to ship, commit and push first (or consciously deploy dirty tree — prefer clean `origin` HEAD).

---

## 2. Rebuild & redeploy (production)

```bash
cd /home/ec2-user/pen-test-portal

# Ensure MySQL is up
sudo docker compose ps
# if not healthy:
# sudo docker compose up -d

# Build client + bundle server → dist/
pnpm build

# Roll the systemd unit onto the new dist/
sudo systemctl restart pentest-portal

# Give Node a couple of seconds to listen
sleep 3
```

If `.env` or systemd drop-ins changed:

```bash
sudo systemctl daemon-reload   # only if unit files changed
sudo systemctl restart pentest-portal
```

**Do not** leave `pnpm dev` running against the same port while production is expected — stop it first (`pkill -f "tsx watch server/_core"`) then start the unit.

---

## 3. Health checks (must pass)

Run these after every redeploy. Treat any failure as a blocked release until investigated.

```bash
cd /home/ec2-user/pen-test-portal

# 3.1 systemd
systemctl is-active pentest-portal          # expect: active
systemctl --no-pager -l status pentest-portal | head -30

# 3.2 local HTTP
curl -sS -o /dev/null -w "local_root=%{http_code}\n" http://127.0.0.1:3000/
# expect: local_root=200

# 3.3 tRPC health
curl -sS "http://127.0.0.1:3000/api/trpc/system.health?input=%7B%22json%22%3A%7B%22timestamp%22%3A$(date +%s000)%7D%7D"
# expect JSON containing "ok":true

# 3.4 public site
curl -sS -o /dev/null -w "https_root=%{http_code}\n" --max-time 15 https://ghoststrike.tech/
curl -sS -o /dev/null -w "https_methodology=%{http_code}\n" --max-time 15 https://ghoststrike.tech/methodology
# expect: 200

# 3.5 MySQL
sudo docker compose ps
# expect mysql STATUS: Up ... (healthy)

# 3.6 Nginx
systemctl is-active nginx
sudo nginx -t

# 3.7 Startup features (from logs)
sudo journalctl -u pentest-portal -n 40 --no-pager
# expect lines like:
#   Server running on http://localhost:3000/
#   [ScheduleRunner] started ...
#   [CapabilityUpdater] scheduled cron "0 0 3 * * *" (UTC) ...
```

### Quick one-liner (copy/paste after `pnpm build` + restart)

```bash
systemctl is-active pentest-portal \
  && curl -sf -o /dev/null http://127.0.0.1:3000/ \
  && curl -sf "http://127.0.0.1:3000/api/trpc/system.health?input=%7B%22json%22%3A%7B%22timestamp%22%3A$(date +%s000)%7D%7D" | grep -q '"ok":true' \
  && curl -sf -o /dev/null --max-time 15 https://ghoststrike.tech/ \
  && echo "HEALTH_OK" || echo "HEALTH_FAIL"
```

---

## 4. Optional post-deploy checks

```bash
# Scanner binaries available to the service PATH
# (service drop-in adds /usr/local/bin and ~/.local/bin)
for b in nuclei nikto wapiti semgrep trivy osv-scanner gitleaks zap.sh testssl.sh; do
  command -v "$b" >/dev/null && echo "OK $b" || echo "MISSING $b"
done

# Overview PDF endpoint (public)
curl -sS "http://127.0.0.1:3000/api/trpc/system.getOverviewPdf" | head -c 80; echo

# Capability / intel status (requires admin session — use Admin UI)
# Admin → Update Pen Test Capabilities / last intel refresh display
```

---

## 5. Rollback

```bash
cd /home/ec2-user/pen-test-portal
git log -5 --oneline
git checkout <previous-good-sha>   # or: git revert / reset per team policy
pnpm build
sudo systemctl restart pentest-portal
# re-run section 3 health checks
```

If the unit will not start:

```bash
sudo journalctl -u pentest-portal -n 100 --no-pager
sudo systemctl status pentest-portal --no-pager
```

---

## 6. Known weaknesses & watch items

Track these so they are not forgotten after a “green” HTTP check.

| Area | Severity | What’s wrong | Mitigation / follow-up |
|------|----------|--------------|------------------------|
| **Rate-limit IPv6 keyGenerator** | Medium | Startup logs `ERR_ERL_KEY_GEN_IPV6` from `express-rate-limit` — custom key generator may not use `ipKeyGenerator`, so IPv6 clients could bypass limits. App still starts. | Fix keyGenerator in security middleware; verify warning gone after restart. |
| **OAuth not configured** | Medium (prod auth) | Logs: `OAUTH_SERVER_URL is not configured`. Dev/admin login may work; production OAuth SSO will not. | Set `OAUTH_SERVER_URL` / portal OAuth env vars when leaving admin/dev bypass. |
| **Missing Trivy** | Medium (SCA depth) | `trivy` not on PATH — dependency DB refresh + Trivy SCA path unavailable; OSV-Scanner still present. | Install Trivy; ensure `/usr/local/bin` on service PATH (already via drop-in). |
| **Missing Gitleaks** | Medium (secrets) | Repo secrets fall back to Semgrep `p/secrets` only. | Install Gitleaks binary for stronger secret detection. |
| **Express clearCookie deprecation** | Low | `res.clearCookie` with `maxAge` warns (Express v5). | Remove `maxAge` from clearCookie options. |
| **Large JS chunks** | Low | Vite warns chunks &gt; 500 kB. | Optional code-splitting later; not a deploy blocker. |
| **Scan tool coverage is host-dependent** | High (scan quality) | Full-mode quality depends on binaries installed on this EC2. Missing tools = skipped phases / info findings. | Keep the tool checklist in §4 green; document intentional omissions. |
| **Capability cron needs process up at 03:00 UTC** | Medium | Daily intel refresh is **in-process**. If the unit is down at 03:00 UTC, that day’s KEV/EPSS/Nuclei refresh is skipped until next day or Admin manual update. | Keep `Restart=always`; after outages run Admin → Update Pen Test Capabilities. |
| **No AWS key validation (by design)** | Info | Exposed AWS keys are reported masked; Ghoststrike never calls AWS with them (protects canaries / real keys). | Infra honeytoken *use* detection stays in `canaries.md` (CloudTrail), not this portal. |
| **Nginx proxy timeouts** | Medium (UX) | Long scans can 504 if nginx timeouts are short. | Confirm `proxy_read_timeout` ≥ 300s in live nginx conf (`deploy/nginx-ghoststrike.conf`). |
| **Single-host deploy** | High (availability) | One EC2, no blue/green. Restart = brief blip. | Accept for now; consider second instance / ALB later. |
| **Secrets in `.env` on host** | High (ops) | Production secrets live in `/home/ec2-user/pen-test-portal/.env`. | Keep permissions tight; never commit; prefer SSM/Secrets Manager long-term. |
| **Legacy `CICD_API_KEY`** | Medium (ops) | Env master CI key is limited (no free-form URLs; no cross-user scan IDOR). Prefer **Integrations → CI/CD API keys** (org-bound). | Avoid setting `CICD_API_KEY` in production when possible. |

---

## 7. Related docs

| Doc | Purpose |
|-----|---------|
| [`deploy/README.md`](deploy/README.md) | EC2 layout, nginx, SSL, optional scanners |
| [`EC2_SETUP.md`](EC2_SETUP.md) | Dev-oriented setup on this host |
| [`docs/PENTEST_METHODOLOGY.md`](docs/PENTEST_METHODOLOGY.md) | How scans work + daily 03:00 UTC intel cron |
| [`canaries.md`](canaries.md) | Infra AWS honeytoken plan (not deployed by Ghoststrike) |
| [`CHANGELOG.md`](CHANGELOG.md) | What changed in recent releases |

---

## 8. Definition of a successful redeploy

- [ ] `pnpm build` completed without error
- [ ] `pentest-portal` is `active`
- [ ] Local `/` and `system.health` return OK
- [ ] `https://ghoststrike.tech/` returns 200
- [ ] MySQL container healthy
- [ ] Logs show ScheduleRunner + CapabilityUpdater started
- [ ] Known weaknesses above reviewed (no new regressions in journalctl)

---

*Last verified procedure shape: 2026-11-27 — rebuild of `078ba34` on this host returned local/HTTPS 200, health `ok`, CapabilityUpdater cron `0 0 3 * * *` UTC, MySQL healthy; Trivy and Gitleaks still missing.*
