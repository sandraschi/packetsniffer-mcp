# packetsniffer-mcp

MCP server for local network packet capture and PCAP file analysis.

**Stack:** Python 3.12+ · FastMCP 3.4 · FastAPI · prefab-ui · Multi-provider LLM · Sampling · CodeMode (`--agentic`)

## What can I do with this?

A network debugger you can ask questions of. The agent drives Scapy via one
portmanteau tool (`packetsniffer_ops`) instead of you wrangling Wireshark/tshark:

| Scenario | Call |
|----------|------|
| **"What is in this capture file?"** — analyze any `.pcap`/`.pcapng` (yours, a colleague's, a router export). No admin needed. | `packetsniffer_ops(operation="analyze_pcap", file_path="C:/captures/router.pcap")` |
| **"What is phoning home?"** — watch DNS queries to find which app contacts which domain. Pass `save_path` to keep the raw capture as evidence. | `packetsniffer_ops(operation="sniff", filter_expr="udp port 53", count=200, timeout=120, save_path="C:/captures/dns.pcap")` |
| **"Watch it in the background"** — start a capture, don't block the agent. Poll, then collect. Survives across agent sessions in HTTP daemon mode. | `start_capture` → `capture_status` → `stop_capture` |
| **"Decode it deeply"** — after a capture, extract decoded fields Scapy misses: full DNS answers, HTTP requests, and **TLS SNI hostnames** (catches encrypted phone-home domains). Requires tshark (ships with Wireshark). | `packetsniffer_ops(operation="decode_pcap", file_path="C:/captures/dns.pcap", limit=100)` |
| **"Why is my service unreachable?"** — capture traffic to one port and see whether packets arrive at all, and how the TCP handshake behaves. | `packetsniffer_ops(operation="sniff", filter_expr="tcp port 10813", count=30)` |
| **"What is on my network?"** — list interfaces before capturing. | `packetsniffer_ops(operation="list_interfaces")` |

Results come back as structured JSON (flows, protocol mix, per-packet summaries)
so the agent can interpret them directly — no pcap GUI needed.

**Limits / requirements:**
- `analyze_pcap` and `decode_pcap` work on files anywhere, no privileges.
- `decode_pcap` needs **tshark** on PATH (ships with Wireshark — `winget install Wireshark`).
  Without it, the op returns a clean `missing_dependency` error, nothing else breaks.
- Live `sniff` / `start_capture` require **administrator privileges**, and on
  Windows the **Npcap** driver (Wireshark's capture backend).
- Loopback capture (`127.0.0.1`) is unreliable on Windows — this tool shines
  on WiFi/LAN/DNS traffic and offline capture files, not localhost webapp
  debugging.
- Capture defaults are bounded: `count` max 1000, `timeout` max 300s. Raise
  the ceilings via `PACKETSNIFFER_MCP_MAX_SNIFF_COUNT` /
  `PACKETSNIFFER_MCP_MAX_SNIFF_SECONDS` for long-running captures.
- Background captures live in the server process: run the HTTP daemon
  (`start.ps1` / `--http`) for captures that outlive a single agent session.
  `stop_capture` takes effect on the next packet — with no traffic on the
  interface it finishes at the timeout.

## Install

```powershell
uv sync --extra dev
pre-commit install
```

## Run

```powershell
# stdio (Claude Desktop / Cursor)
uv run python -m packetsniffer_mcp

# HTTP + REST API (direct access)
uv run python -m packetsniffer_mcp --http --port 10920

# CodeMode agentic discovery
uv run python -m packetsniffer_mcp --agentic

# Dev launcher (auto-opens browser; `-Headless` to skip)
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
