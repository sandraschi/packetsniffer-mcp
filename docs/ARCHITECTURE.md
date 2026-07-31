# packetsniffer-mcp — Architecture

## Package Layout

```
src/packetsniffer_mcp/
├── __init__.py          # Version
├── __main__.py          # python -m entry
├── server.py            # Top-level runner
├── config.py            # Sampling config
├── sampling.py          # OpenAI-compatible handler
├── mcp_instance.py      # FastMCP singleton
├── tool_registration.py # Import all tools
├── fleet_surface.py     # Prompts, resources, prefab card
├── prefabs.py           # Prefab UI card builders
├── transport.py         # Dual transport (stdio/HTTP) + CodeMode
└── tools/
    ├── __init__.py
    ├── help_tools.py    # help + status
    └── agentic_workflow.py  # SEP-1577 sampling workflow
```

## Transport

- **stdio**: Default — for Claude Desktop, Cursor, Windsurf
- **HTTP**: Via `--http --port <port>` — for REST API integration
- **PyInstaller**: `run_server.py` — detects `MCP_PORT`/`PORT` for HTTP, falls back to stdio

## Sampling

Configured via `PACKETSNIFFER_MCP_SAMPLING_BASE_URL` (default: Ollama on localhost:11434).
Also works with LM Studio (`http://localhost:1234/v1`) and any OpenAI-compatible endpoint.
