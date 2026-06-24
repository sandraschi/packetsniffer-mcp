# Product Requirements Document: packetsniffer-mcp

## Overview
MCP server for local network packet capture and PCAP file analysis

## Target Audience
- AI agents (Claude Desktop, Cursor, Windsurf)
- Fleet MCP servers consuming this server
- Developers integrating via MCP protocol

## Core Features
1. **FastMCP 3.4+**: Full MCP protocol with tools, prompts, resources
2. **Transport**: stdio (HTTP optional)
3. **Sampling**: OpenAI-compatible endpoint (Ollama, LM Studio)
4. **Prefab UI**: Rich in-chat cards for status/discovery
5. **CodeMode**: BM25 agentic discovery via `--agentic`
6. **Fleet integration**: Glama registry, llms.txt, mcpb packaging

## Success Metrics
- All tools return structured dicts with success/data/error
- Sampling fallback works when client lacks sampling support
- mcpb pack produces valid .mcpb bundle
