# packetsniffer-mcp — Tool Reference

## Core Tools

### `packetsniffer_ops`
One portmanteau tool (`operation` enum). Network: `list_interfaces`, `sniff`, `start_capture`, `capture_status`,
`stop_capture`, `decode_pcap` (needs tshark), `analyze_pcap`. Hardware reverse engineering: `usb_list_hubs`,
`usb_capture` (USBPcap; unverified live), `usb_payloads`, `btsnoop_payloads`, `diff_captures`. Every result is
`{"success", "operation", "data"}`; failures carry `error_type` (`invalid_request`, `invalid_capture`,
`missing_dependency`, `capture_tool_failed`, `empty_capture`, `no_hubs`, `invalid_hub`, `invalid_devices`) and,
where useful, `suggestions`. Full parameter list is in the tool's schema.

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
