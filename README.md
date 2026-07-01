# AgentGuard

A semantic circuit breaker and policy proxy for AI agents. AgentGuard sits between an agent framework and its MCP tool servers, inspecting every `tools/call` before it executes.

Landing page: https://agentguard-brown.vercel.app/

## What it does

Every call to `/mcp` passes through, in order:

1. **Policy check** (`internal/policy`) — hard-blocks any tool on the configured deny-list.
2. **Redaction** (`internal/redactor`) — scrubs secrets (API keys, DB URIs, bearer tokens, emails) out of tool arguments before they're logged or forwarded.
3. **Circuit breaker** (`internal/breaker`) — trips if a session makes more than `max_calls_per_window` calls to the same method within `window_seconds`, using Upstash Redis if configured, or an in-memory fallback otherwise. Stops runaway/looping agents.
4. **Sandbox** (`internal/sandbox`) — tools listed under `tools.destructive` in the policy YAML are executed inside a Landlock-restricted context on Linux (falls back to unrestricted execution with a warning on macOS/Windows for local dev).
5. **Forward to upstream** — the checked, redacted call is forwarded to your real MCP server (`AGENTGUARD_UPSTREAM_URL`), and its response is relayed back.

All decisions are logged asynchronously to Supabase (if configured) and kept in an in-memory ring buffer for the `/logs/recent` dashboard endpoint.

## Setup

### 1. Requirements

- Go 1.24+
- (Optional) an [Upstash Redis](https://upstash.com/) database for distributed rate-limiting across multiple AgentGuard instances
- (Optional) a [Supabase](https://supabase.com/) project for persistent audit logs — schema in `deploy/supabase-schema.sql`

### 2. Configure

Copy and edit `backend/config/agentguard.yaml` to set your blocked/destructive/exempt tool lists, breaker thresholds, and redaction rules.

Set these environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `AGENTGUARD_AUTH_SECRET` | **Yes** | Shared secret that callers must send as `Authorization: Bearer <secret>`. The proxy rejects all `/mcp` requests until this is set. |
| `AGENTGUARD_UPSTREAM_URL` | **Yes** | The real MCP server AgentGuard forwards approved calls to. |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | No | Enables distributed circuit-breaker state. Without these, rate limiting falls back to per-instance memory. |
| `SUPABASE_URL` / `SUPABASE_KEY` | No | Enables persistent audit logging. Without these, logs only live in memory. |
| `AGENTGUARD_ALERT_WEBHOOK` | No | Slack/Discord webhook fired when the breaker trips. |

### 3. Run

```bash
cd backend
go run ./cmd/proxy --config config/agentguard.yaml
```

The proxy listens on `:8080` by default (`server.port` in the YAML). Point your agent framework's MCP client at `http://localhost:8080/mcp` instead of your real MCP server directly.

### 4. Deploy

`deploy/cloud-run-deploy.sh` deploys the backend to Google Cloud Run. The `frontend/` directory is a static dashboard you can host anywhere (e.g. Vercel, Firebase Hosting) — it reads from the `/logs/recent` and `/policy` endpoints, which are CORS-enabled for that purpose.

## Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/mcp` | POST | The proxied MCP endpoint. Requires `Authorization: Bearer <AGENTGUARD_AUTH_SECRET>`. |
| `/logs/recent` | GET | Last 50 logged calls (session, method, status, timestamp), for the dashboard. |
| `/policy` | GET | Current blocked/destructive/exempt tool lists. |

## Status

Early stage — this is a working proxy with real auth, forwarding, and Landlock sandboxing, but it hasn't been used against production traffic yet. Treat the "Enterprise" tier on the landing page as aspirational until there's more real-world mileage on it.

## License

MIT — see `LICENSE`.
