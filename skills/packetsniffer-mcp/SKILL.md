# PacketsnifferMcp Agent Skill

MCP server for local network packet capture and PCAP file analysis

## FastMCP 3.4 surface
- Sampling via `PACKETSNIFFER_MCP_SAMPLING_BASE_URL` (Ollama/LM Studio)
- `agentic_packetsniffer_mcp_workflow` for multi-step tasks
- Prefab: `packetsniffer_mcp_status_card`
- CodeMode: `--agentic` or `MCP_AGENTIC=1`

## Quick start
```powershell
uv sync
uv run python -m packetsniffer_mcp
```
