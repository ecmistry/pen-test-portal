# PenTest Portal — EC2 / galaxy-api.tech deploy

## What’s in place

- **MySQL**: Runs in Docker via `docker-compose` (image `mysql:8.0`). Started automatically at boot by `pentest-portal-mysql.service`.
- **App**: Node.js app runs under systemd as `pentest-portal.service` (port 3000), starts after MySQL.
- **Nginx**: Reverse proxy for `galaxy-api.tech` (and `www.galaxy-api.tech`):
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
   Leave this terminal open; the server runs at http://localhost:3000 (nginx still proxies galaxy-api.tech to it).

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

## DNS and firewall

- **DNS**: Point `galaxy-api.tech` (and optionally `www.galaxy-api.tech`) to this server’s **public IP**.
- **Security group**: Allow **inbound TCP 80 and 443** so nginx can receive HTTP (redirect) and HTTPS traffic.

## Login

With `DEV_BYPASS_AUTH=true` and `VITE_DEV_LOGIN=true` in `.env`, use **Dev Login** on the portal to sign in without OAuth. For production OAuth, set `VITE_APP_ID`, `OAUTH_SERVER_URL`, and `VITE_OAUTH_PORTAL_URL` and switch off the dev bypass.
