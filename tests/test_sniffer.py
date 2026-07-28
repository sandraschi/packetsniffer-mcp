"""Verify sniffer tools register and return expected shapes."""

import asyncio

from packetsniffer_mcp.tools.sniffer_tools import packetsniffer_ops


def test_list_interfaces():
    """List interfaces should return a list of active network adapters."""
    result = asyncio.run(packetsniffer_ops(operation="list_interfaces"))
    assert result["success"]
    assert result["operation"] == "list_interfaces"
    assert isinstance(result["data"], list)
    if len(result["data"]) > 0:
        # Check that interface records contain the expected fields
        iface = result["data"][0]
        assert "id" in iface
        assert "name" in iface
        assert "description" in iface
        assert "ip" in iface
        assert "mac" in iface


def test_analyze_pcap_nonexistent():
    """Analyzing a nonexistent PCAP file should return a clean error dict."""
    result = asyncio.run(packetsniffer_ops(operation="analyze_pcap", file_path="nonexistent_file_123.pcap"))
    assert not result["success"]
    assert "error" in result
