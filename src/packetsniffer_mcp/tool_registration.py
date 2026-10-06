"""Register tools and fleet surface after FastMCP exists."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_registered = False


def register_all_tools(mcp=None) -> None:
    global _registered
    if _registered:
        return

    if mcp is None:
        from packetsniffer_mcp.mcp_instance import get_mcp

        mcp = get_mcp()

    # Tool imports trigger decorator registration - keep in order
    import packetsniffer_mcp.tools.agentic_workflow as _aw  # noqa: F401, I001
    import packetsniffer_mcp.tools.help_tools as _ht  # noqa: F401
    import packetsniffer_mcp.tools.chat_tool as _ct  # noqa: F401
    import packetsniffer_mcp.tools.sniffer_tools as _st  # noqa: F401
    from packetsniffer_mcp.fleet_surface import register_fleet_surface

    register_fleet_surface(mcp)
    _registered = True
    logger.info("Tools and fleet surface registered")
