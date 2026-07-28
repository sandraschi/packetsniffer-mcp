"""Verify tools register and return expected shapes."""

import asyncio


def test_help_tool():
    """Help tool should return tools list."""
    from packetsniffer_mcp.tools.help_tools import help

    result = asyncio.run(help())
    assert result["success"]
    assert "tools" in result


def test_status_tool():
    """Status tool should report healthy."""
    from packetsniffer_mcp.tools.help_tools import status

    result = asyncio.run(status())
    assert result["success"]
    assert result["healthy"]
    assert "version" in result
