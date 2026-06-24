"""MCP server entry point."""

from __future__ import annotations

from packetsniffer_mcp.mcp_instance import get_mcp
from packetsniffer_mcp.transport import run


def main() -> None:
    run(get_mcp(), "packetsniffer-mcp")


if __name__ == "__main__":
    main()
