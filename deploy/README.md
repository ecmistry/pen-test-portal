# PenTest Portal — EC2 / ghoststrike.tech deploy

## What’s in place

- **MySQL**: Runs in Docker via `docker-compose` (image `mysql:8.0`). Started automatically at boot by `pentest-portal-mysql.service`.
- **App**: Node.js app runs under systemd as `pentest-portal.service` (port 3000), starts after MySQL.
- **Nginx**: Reverse proxy for `ghoststrike.tech` (and `www.ghoststrike.tech`):
  - **HTTPS** on port 443 → `http://127.0.0.1:3000` (Let’s Encrypt certificate).
  - **HTTP** on port 80 redirects to HTTPS.
- **Certbot**: Certificate auto-renewal via `certbot-renew.timer`.

## Useful commands

```bash
# App
sudo systemctl status pentest-portal
sudo systemctl restart pentest-portal
sudo journalctl -u pentest-portal -f

# MySQL (Docker)
cd /home/ec2-user/pen-test-portal && docker-compose ps
docker-compose up -d   # start
docker-compose down    # stop

# Nginx
sudo systemctl status nginx
sudo systemctl reload nginx

# SSL (Let's Encrypt) — renewals are automatic via certbot-renew.timer
sudo certbot renew --dry-run   # test renewal
sudo systemctl status certbot-renew.timer
```

## Running in development (no rebuild/redeploy)

Use dev mode when you want live reload (Vite HMR + tsx watch) and no manual build/restart.

1. **Stop production** and start dev:
   ```bash
   cd /home/ec2-user/pen-test-portal
   sudo systemctl stop pentest-portal
   pnpm dev
   ```
   Leave this terminal open; the server runs at http://localhost:3000 (nginx still proxies ghoststrike.tech to it).

2. **Run dev in the background** (keeps running after you disconnect):
   ```bash
   cd /home/ec2-user/pen-test-portal
   sudo systemctl stop pentest-portal
   nohup pnpm dev > dev-server.log 2>&1 &
   tail -f dev-server.log   # optional: watch logs
   ```

3. **Stop dev and go back to production**:
   ```bash
   pkill -f "tsx watch server/_core"   # or kill the node process on port 3000
   cd /home/ec2-user/pen-test-portal && pnpm build
   sudo systemctl start pentest-portal
   ```

## After code or env changes (production)

```bash
cd /home/ec2-user/pen-test-portal
pnpm build
sudo systemctl restart pentest-portal
```

## Nginx proxy timeouts

If scan pages show **504 Gateway Time-out** or **ERR_EMPTY_RESPONSE** while a scan is running, increase proxy timeouts in your nginx server block (e.g. in `/etc/nginx/conf.d/ghoststrike.conf`). Inside the `location /` block that has `proxy_pass http://127.0.0.1:3000`, add:

```nginx
proxy_connect_timeout 75s;
proxy_send_timeout 300s;
proxy_read_timeout 300s;
```

Then run `sudo nginx -t && sudo systemctl reload nginx`. The repo’s `deploy/nginx-ghoststrike.conf` includes these. (Certbot may have rewritten your file; re-add the timeouts after any certbot change.)

## DNS and firewall

- **DNS**: Point `ghoststrike.tech` (and optionally `www.ghoststrike.tech`) to this server’s **public IP** (current: **52.56.193.19**).
- **Security group**: Allow **inbound TCP 80 and 443** so nginx can receive HTTP (redirect) and HTTPS traffic.

## Optional scan tools (full-mode comprehensiveness)

For the most comprehensive full-mode scans, install these free tools so the portal can run them:

| Tool   | Purpose                         | Install (example) |
|--------|----------------------------------|-------------------|
| Nikto  | Web server / misconfiguration   | Clone [sullo/nikto](https://github.com/sullo/nikto), symlink to `/usr/local/bin/nikto` |
| Nuclei | CVE / misconfig / takeover      | [Releases](https://github.com/projectdiscovery/nuclei/releases) → binary in `/usr/local/bin`; run `nuclei -update-templates` or use **Admin → Update scan capabilities** |
| Wapiti | Black-box (SQLi, XSS, XXE, etc.) | `pip install wapiti3`; ensure `wapiti` or `wapiti3` is on PATH or in `/usr/local/bin` |
| ZAP    | OWASP DAST baseline             | [zaproxy.org/download](https://www.zaproxy.org/download/) (e.g. `zap.sh` or `zap-baseline.py` on PATH) |

The portal detects each tool at scan time; if missing, that phase is skipped and (where applicable) an informational finding is recorded.

## Login

With `DEV_BYPASS_AUTH=true` and `VITE_DEV_LOGIN=true` in `.env`, use **Dev Login** on the portal to sign in without OAuth. For production OAuth, set `VITE_APP_ID`, `OAUTH_SERVER_URL`, and `VITE_OAUTH_PORTAL_URL` and switch off the dev bypass.
