# EC2 Development Setup

This document describes the setup on the EC2 instance for pen-test-portal development.

## SSH Connection

```bash
ssh gravitee-pen-test-portal
```

## Project Location

```
~/pen-test-portal
```

## Installed Tools

- **Node.js** 20.x (via NodeSource)
- **pnpm** (global)
- **Git**
- **Docker** + **Docker Compose**
- **MySQL 8** (via Docker)

## Quick Start on EC2

```bash
# SSH in
ssh gravitee-pen-test-portal

# Navigate to project
cd ~/pen-test-portal

# Ensure MySQL is running
sudo docker-compose up -d

# Start dev server (use tmux/screen for long-running sessions)
pnpm dev
```

The app runs at **http://localhost:3000** (or the EC2's public IP if you configure port forwarding / security group).

## Environment

- `.env` is configured for dev with `DEV_BYPASS_AUTH=true` and `VITE_DEV_LOGIN=true`
- MySQL: `mysql://pentest:pentest@localhost:3306/pentest_portal`
- Use **Dev Login** to sign in without OAuth

## Useful Commands

| Command | Description |
|---------|-------------|
| `pnpm dev` | Start dev server |
| `pnpm build` | Build for production |
| `pnpm start` | Run production server |
| `pnpm db:migrate` | Run migrations |
| `sudo docker-compose up -d` | Start MySQL |
| `sudo docker-compose down` | Stop MySQL |

## Running Dev Server in Background

Use `tmux` or `screen` to keep the dev server running after disconnecting:

```bash
# Install tmux if needed
sudo dnf install -y tmux

# Start a session
tmux new -s pentest

# Run dev server
cd ~/pen-test-portal && pnpm dev

# Detach: Ctrl+B, then D
# Reattach: tmux attach -t pentest
```

## Accessing from Your Mac

To access the app from your Mac, either:

1. **SSH port forwarding**: `ssh -L 3000:localhost:3000 gravitee-pen-test-portal` then open http://localhost:3000
2. **EC2 public IP**: Add port 3000 to the EC2 security group and access `http://<ec2-public-ip>:3000`
