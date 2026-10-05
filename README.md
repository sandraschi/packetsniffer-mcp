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
| **"What bytes does this app send my USB device?"** — pull the host-to-device data out of a USBPcap capture, with per-endpoint totals and any captured device/interface descriptors (printer class? HID? vendor-specific?). Pure Python, no tshark. | `packetsniffer_ops(operation="usb_payloads", file_path="C:/captures/02-dot.pcap", export_path="C:/captures/02-dot.bin")` |
| **"What does it send over Bluetooth serial?"** — RFCOMM (serial port profile) data from a Bluetooth HCI capture (btsnoop log from an Android phone, or Wireshark pcap/pcapng). | `packetsniffer_ops(operation="btsnoop_payloads", file_path="C:/captures/btsnoop_hci.log")` |
| **"Which bytes encode the dot?"** — diff two captures (blank label vs one-dot label): shared prefix/suffix, changed byte ranges, per-transfer differences. | `packetsniffer_ops(operation="diff_captures", file_path="C:/captures/01-blank.pcap", file_path_b="C:/captures/02-dot.pcap")` |
| **"Capture USB while I operate the device"** — wraps USBPcap's command line for a fixed duration. **Unverified live** (needs the USBPcap driver, administrator rights). | `packetsniffer_ops(operation="usb_list_hubs")` then `packetsniffer_ops(operation="usb_capture", usb_hub="\\\\.\\USBPcap1", timeout=30, save_path="C:/captures/02-dot.pcap")` |

Results come back as structured JSON (flows, protocol mix, per-packet summaries)
so the agent can interpret them directly — no pcap GUI needed.

**Hardware reverse engineering (USB / Bluetooth):**
- `usb_payloads`, `btsnoop_payloads` and `diff_captures` work on files anywhere, with no privileges and no tshark.
  They are tested against synthetic captures (USBPcap header layout cross-checked against scapy; RFCOMM checksums
  against the well-known DLCI 0 frames), not yet against a capture from real hardware.
- `usb_capture` / `usb_list_hubs` drive `USBPcapCMD.exe` (`winget install desowin.USBPcap`; a capture driver,
  administrator rights, sometimes a reboot). They are tested through a fake executable only.
- Bluetooth: the capture must start **before** the device connects, or the L2CAP channel table is missing and only
  frames whose checksum verifies are kept. Classic Bluetooth cannot be sniffed from Windows; use an Android phone's
  HCI snoop log. Credit-based flow control bytes are handled; unusual RFCOMM streams may not decode.
- Method and capture protocol: see the DYMO MobileLabeler plan in devices-mcp, `docs/LABEL_PRINTER_REVERSE_ENGINEERING.md`.

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
