<div align="center">

# SecOps Console — Log Forwarder

<img src="https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js"/>
&nbsp;
<img src="https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript"/>
&nbsp;
<img src="https://img.shields.io/badge/CLI-Tool-0f172a?style=for-the-badge" alt="CLI"/>

**A lightweight Splunk Universal Forwarder–style agent for SecOps Console.**  
Tail log files · Transform and filter · Forward to the SecOps API.

</div>

---

## Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Configuration Files](#configuration-files)
- [CLI Commands](#cli-commands)
- [Deployment Examples](#deployment-examples)

---

## Overview

The SecOps Forwarder is a standalone CLI agent that:

1. **Tails** log files defined in `inputs.conf`
2. **Transforms** raw lines using extraction rules from `props.conf`
3. **Forwards** events to your SecOps Console backend via HTTP API

It maintains file checkpoints so it survives restarts without re-reading already-sent data.

```
/var/log/auth.log ──► Forwarder ──► POST /api/ingest-log ──► SecOps Backend
/var/log/nginx/  ──► (tail + ──►
/app/logs/*.log  ──►  transform) ──►
```

---

## Quick Start

### Using the start script

```bash
# From the project root:
bash secops-forwarder/start.sh

# Or from inside the forwarder directory:
cd secops-forwarder
bash start.sh
```

### Manual setup

```bash
cd secops-forwarder

# 1. Install dependencies
npm install

# 2. Configure outputs (set your SecOps Console URL and API key)
cp conf/outputs.conf.example conf/outputs.conf
nano conf/outputs.conf

# 3. Configure inputs (add the log files you want to tail)
nano conf/inputs.conf

# 4. Build
npm run build

# 5. Start
npm run start
```

---

## Configuration Files

All configuration lives in the `conf/` directory. Files use an INI-style format similar to Splunk's `.conf` files.

### `conf/outputs.conf` — Where to send logs

```ini
[secops_console]
url = http://localhost:8080
api_key = your-api-key-here
batch_size = 50
flush_interval = 2000
retry_attempts = 3
retry_delay = 1000
```

| Key | Description |
|---|---|
| `url` | Base URL of your SecOps Console backend |
| `api_key` | API key from **Settings → API Keys** in the console |
| `batch_size` | Number of events to batch before flushing (default: `50`) |
| `flush_interval` | Max milliseconds between flushes (default: `2000`) |
| `retry_attempts` | Number of delivery retries on failure (default: `3`) |
| `retry_delay` | Milliseconds between retries (default: `1000`) |

---

### `conf/inputs.conf` — What to tail

```ini
# Tail a single file
[monitor:///var/log/auth.log]
source = syslog
index = main
disabled = false

# Tail a directory (all .log files)
[monitor:///var/log/nginx/]
source = nginx_access
index = main

# Tail application logs
[monitor:///opt/myapp/logs/*.log]
source = app_json
disabled = false
```

| Key | Description |
|---|---|
| `source` | Log format hint sent to the SecOps parser registry |
| `index` | Logical grouping name (informational) |
| `disabled` | Set to `true` to skip this input without removing it |

**Supported source types:** `syslog`, `windows_eventlog`, `cef`, `ecs`, `leef`, `cloudtrail`, `dns`, `generic`

---

### `conf/props.conf` — Field extraction rules

```ini
# Extract fields from a custom log format
[myapp_logs]
TRANSFORMS-extract = extract_myapp_fields

[extract_myapp_fields]
REGEX = (\w+)\s+user=(\S+)\s+action=(\S+)
FORMAT = eventType::$1 username::$2 action::$3

# Override source type for specific paths
[source::/var/log/custom-app/*.log]
sourcetype = syslog
```

---

## CLI Commands

```bash
# Start the forwarder (reads conf/ directory)
node dist/cli.js start

# Check forwarder status and current checkpoint positions
node dist/cli.js status

# Validate configuration files without starting
node dist/cli.js test-config

# Development mode (no build required)
npx tsx src/cli.ts start
```

---

## Deployment Examples

### As a systemd service (Linux)

```ini
# /etc/systemd/system/secops-forwarder.service
[Unit]
Description=SecOps Console Log Forwarder
After=network.target

[Service]
Type=simple
User=secops-forwarder
WorkingDirectory=/opt/secops-forwarder
ExecStart=/usr/bin/node dist/cli.js start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now secops-forwarder
sudo journalctl -u secops-forwarder -f
```

### In a Docker container

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install && npm run build
VOLUME ["/app/conf", "/app/checkpoints"]
CMD ["node", "dist/cli.js", "start"]
```

```bash
docker run -d \
  -v ./conf:/app/conf \
  -v ./checkpoints:/app/checkpoints \
  secops-forwarder
```

### On a remote Linux server

```bash
# Copy the forwarder to the server
scp -r secops-forwarder user@server:/opt/

# SSH in, configure, and start
ssh user@server
cd /opt/secops-forwarder
npm install && npm run build
node dist/cli.js test-config
node dist/cli.js start
```

---

## How It Works

```
Startup
  │
  ├── Read and validate conf/*.conf
  ├── Restore file checkpoints from checkpoints/ directory
  └── Start file monitor for each [monitor://...] in inputs.conf

Per-file monitoring loop
  │
  ├── Detect new lines since last checkpoint
  ├── Apply props.conf extraction rules
  ├── Batch events up to batch_size or flush_interval
  └── POST to SecOps Console API → update checkpoint on success

On failure
  └── Retry up to retry_attempts times, then log and continue
```

Checkpoints are saved in the `checkpoints/` directory (created automatically). They record the byte position in each monitored file, ensuring no events are lost or duplicated across restarts.
