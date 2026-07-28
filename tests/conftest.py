"""Pytest configuration and initialization."""

from packetsniffer_mcp.mcp_instance import get_mcp

# Initialize the FastMCP singleton so that top-level tool imports during test collection do not crash
get_mcp()
