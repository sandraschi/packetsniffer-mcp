# packetsniffer-mcp

MCP server for local network packet capture and PCAP file analysis

**Stack:** Python 3.12+ · FastMCP 3.4 · FastAPI · prefab-ui · Multi-provider LLM · Sampling · CodeMode (`--agentic`)

## Install

```powershell
uv sync --extra dev
pre-commit install
```

## Run

```powershell
# stdio (Claude Desktop / Cursor)
uv run python -m packetsniffer_mcp

# HTTP + REST API (Tauri / webapp / direct access)
uv run python -m packetsniffer_mcp --http --port 10800

# CodeMode agentic discovery
uv run python -m packetsniffer_mcp --agentic

# Dev launcher (auto-opens browser)
.\start.ps1
```

## LLM Providers

Auto-detects local providers (Ollama on :11434, LM Studio on :1234).
Configure via environment variables:

| Variable | Purpose |
|----------|---------|
| `PACKETSNIFFER_MCP_LLM_PROVIDER` | ollama \| lmstudio \| openai \| anthropic \| google |
| `PACKETSNIFFER_MCP_LLM_MODEL` | Override model name |
| `PACKETSNIFFER_MCP_LLM_API_KEY` | API key (cloud providers) |

Cloud providers detect their standard env vars: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`.

## API Endpoints (HTTP mode)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/diagnostics` | Full diagnostics (LLM, tools, system) |
| GET | `/api/v1/tools` | List all MCP tools |
| GET | `/api/v1/providers` | List LLM providers + presets |
| POST | `/api/v1/chat` | Chat with LLM (supports streaming) |

## Fleet Surface

| Feature | Entry |
|---------|--------|
| Help | `help` tool |
| Status | `status` tool |
| Prefab card | `packetsniffer_mcp_status_card` |
| Chat | `chat` tool (multi-provider LLM) |
| Agentic | `agentic_packetsniffer_mcp_workflow` |
| Skills | `resource://packetsniffer-mcp/skills` |
| Capabilities | `resource://packetsniffer-mcp/capabilities` |
| CodeMode | `--agentic` or `MCP_AGENTIC=1` |

## License

MIT © 2026 MCP Studio
