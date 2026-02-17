## Watchtower MCP

Compose: `Watchtower MCP/docker-compose.yml` (use `docker compose`; `docker-compose` is not installed)

### Layout
```text
/etc/00Apps/Watchtower MCP/
  AGENTS.md
  README.md
  .env.example
  docker-compose.yml
  aeriswt/
    Dockerfile
    server.py
    watchtower-api-openapi.yaml
```

### Run
```bash
cd "/etc/00Apps/Watchtower MCP"
cp .env.example .env
# edit .env first
docker compose up -d --build
```

### Verify
```bash
cd "/etc/00Apps/Watchtower MCP"
docker compose ps
curl -i http://localhost:8000/health
```

### Update
```bash
cd "/etc/00Apps/Watchtower MCP"
docker compose pull
docker compose up -d --build
```

This stack is build-based. `docker compose pull` may report `Skipped` when no `image:` tags are set; use rebuilds (`up -d --build`) as the update mechanism.

### Auth
- MCP inbound auth token: `MCP_BEARER_TOKEN`
- AerisWT upstream credentials: `AERISWT_CLIENT_ID`, `AERISWT_CLIENT_SECRET`

### Status report format
- 🔵 Updated: image changed and container recreated.
- 🟢 Up to date: image unchanged; no recreate needed.
- 🛑 Stopped: stack intentionally remains down.
- ⚠️ Action needed: update/recreate/config failed.
