"""FastMCP singleton - single initialization point."""

from __future__ import annotations

import logging
import threading
from typing import Optional

from fastmcp import FastMCP

from packetsniffer_mcp import __version__
from packetsniffer_mcp.sampling import SamplingHandler

logger = logging.getLogger(__name__)

mcp: FastMCP | None = None


class _Singleton:
    _instance: Optional["_Singleton"] = None
    _lock = threading.Lock()
    _initialized = False

    def __new__(cls) -> "_Singleton":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        if self._initialized:
            return
        sampling_handler = SamplingHandler()
        self.mcp = FastMCP(
            name="packetsniffer-mcp",
            version=__version__,
            sampling_handler=sampling_handler,
            sampling_handler_behavior="fallback",
            instructions=(
                "MCP server for local network packet capture and PCAP file analysis "
                "Prefer prefab card tools for inventories and health. "
                "Use agentic_packetsniffer_mcp_workflow when the client supports sampling."
            ),
            on_duplicate="replace",
        )
        global mcp
        mcp = self.mcp
        from packetsniffer_mcp.tool_registration import register_all_tools

        register_all_tools(self.mcp)
        self._initialized = True
        logger.info("FastMCP initialized: %s v%s", self.mcp.name, self.mcp.version)


def get_mcp() -> FastMCP:
    inst = _Singleton()
    if inst.mcp is None:
        raise RuntimeError("FastMCP failed to initialize")
    return inst.mcp
