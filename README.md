# Watchtower MCP

![MCP Inspector showing generated Watchtower MCP tools](docs/mcp-inspector.png)

Standalone MCP server for Aeris IoT Watchtower API with OpenAPI-driven tool generation.

Watchtower MCP exposes the Watchtower API as a set of callable MCP tools. Instead of hand-writing endpoints, it reads the bundled OpenAPI spec at startup and generates one tool per operation (with a consistent `payload` shape for `path`, `query`, `body`, and `headers`).

The server is designed for local, authenticated use: inbound requests are protected with a static bearer token (`MCP_BEARER_TOKEN`), and upstream calls use OAuth2 client credentials (`AERISWT_CLIENT_ID` / `AERISWT_CLIENT_SECRET`). Many Watchtower endpoints are account-scoped; those tools require `account_id`, which is mapped to `X-Watchtower-Account-Id` automatically.

Use MCP Inspector to quickly browse available tools, see their required inputs, and run real calls against your Watchtower acount without writing client code first.

## Prerequisites

- Docker
- Docker Compose plugin (`docker compose`)

## Quickstart

```bash
cd "Watchtower MCP"
cp .env.example .env
# Edit .env with your real AerisWT credentials and MCP bearer token
docker compose up -d --build
```

## Endpoints

- Health: `http://localhost:8000/health`
- MCP HTTP transport: `http://localhost:8000/mcp`

## Test with MCP Inspector

Use the official MCP Inspector to explore the generated tools:

- Docs: https://modelcontextprotocol.io/docs/tools/inspector#npm-package
- Connect to: `http://localhost:8000/mcp`
- Auth header: `Authorization: Bearer <MCP_BEARER_TOKEN>`

## Verify

```bash
curl -i http://localhost:8000/health
```

Expected body:

```text
OK
```

## Authentication

- Inbound MCP auth uses your local bearer token from `.env`:
  - `Authorization: Bearer <MCP_BEARER_TOKEN>`
- Upstream AerisWT auth uses OAuth2 client credentials:
  - `AERISWT_CLIENT_ID`
  - `AERISWT_CLIENT_SECRET`

## Common Errors

- `401` from token endpoint: wrong `AERISWT_CLIENT_ID` or `AERISWT_CLIENT_SECRET`.
- `403` from API calls: credentials do not have required permissions.
- `429`: rate limit exceeded (10 requests/minute per client and account).
- `413`: too much data requested; use export-style endpoints and poll scheduled report status.
- Account-scoped endpoints require `account_id` (mapped to `X-Watchtower-Account-Id`).

## Stop

```bash
docker compose down
```
