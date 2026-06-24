# packetsniffer-mcp — Tool Reference

## Core Tools

### `help`
List available tools, resources, and CodeMode status.

### `status`
Server health, version, and tool count.

### `agentic_packetsniffer_mcp_workflow`
Multi-step sampling workflow. Requires a sampling-capable MCP client
(Claude Desktop, Cursor with sampling support).

### `packetsniffer_mcp_status_card`
Prefab UI health card rendered in supporting MCP clients.

## Fleet Surface

| Feature | Entry |
|---------|-------|
| Prompts | `packetsniffer_mcp_session` |
| Skills | `resource://packetsniffer-mcp/skills` |
| Capabilities | `resource://packetsniffer-mcp/capabilities` |
| CodeMode | `--agentic` flag or `MCP_AGENTIC=1` |
