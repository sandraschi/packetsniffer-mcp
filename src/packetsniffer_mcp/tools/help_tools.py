"""Core help and status tools."""

from __future__ import annotations

from packetsniffer_mcp.mcp_instance import mcp


@mcp.tool()
async def help() -> dict:
    """List capabilities and fleet surface for PacketsnifferMcp."""
    return {
        "success": True,
        "message": "MCP server for local network packet capture and PCAP file analysis",
        "tools": ["help", "status", "agentic_packetsniffer_mcp_workflow", "packetsniffer_mcp_status_card"],
        "resources": ["resource://packetsniffer-mcp/skills", "resource://packetsniffer-mcp/capabilities"],
        "codemode": "Pass --agentic or set MCP_AGENTIC=1 for CodeMode discovery",
    }


@mcp.tool()
async def status() -> dict:
    """Server health and version."""
    from packetsniffer_mcp import __version__

    tools = await mcp.list_tools() if hasattr(mcp, "list_tools") else []
    count = len(tools) if tools else 0
    return {
        "success": True,
        "healthy": True,
        "version": __version__,
        "tool_count": count,
        "message": "PacketsnifferMcp operational",
    }
