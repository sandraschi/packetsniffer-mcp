"""PyInstaller entry point — dual transport (HTTP when MCP_PORT set, else stdio)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from packetsniffer_mcp.mcp_instance import get_mcp
from packetsniffer_mcp.transport import run

if __name__ == "__main__":
    # Override MCP_PORT if PORT is set (PyInstaller / Tauri convention)
    if "PORT" in os.environ and "MCP_PORT" not in os.environ:
        os.environ["MCP_PORT"] = os.environ["PORT"]
    if "HOST" in os.environ and "MCP_HOST" not in os.environ:
        os.environ["MCP_HOST"] = os.environ["HOST"]

    mcp = get_mcp()
    run(mcp, "packetsniffer-mcp")
