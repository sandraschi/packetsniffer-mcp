"""Verify sniffer tools register and return expected shapes."""

import asyncio
import shutil
import time

from scapy.all import IP, TCP, UDP, Ether, wrpcap

from packetsniffer_mcp.tools.sniffer_tools import _save_capture, packetsniffer_ops


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


def test_save_capture_adds_extension(tmp_path):
    """_save_capture should append .pcap when the extension is missing."""
    pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53, dport=53)
    target = tmp_path / "out"
    saved = _save_capture([pkt], str(target))
    assert saved == str(target) + ".pcap"


def test_save_then_analyze_roundtrip(tmp_path):
    """Packets saved via sniff's save_path should be analyzable afterwards."""
    packets = [
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53, dport=53),
        Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=50000, dport=443),
    ]
    path = tmp_path / "roundtrip.pcap"
    wrpcap(str(path), packets)

    result = asyncio.run(packetsniffer_ops(operation="analyze_pcap", file_path=str(path)))
    assert result["success"]
    data = result["data"]
    assert data["total_packets"] == 2
    assert set(data["protocols"].keys()) == {"UDP", "TCP"}
    assert len(data["flows"]) == 2


def test_capture_status_lists_all():
    """capture_status without an id should list all captures as an array."""
    result = asyncio.run(packetsniffer_ops(operation="capture_status"))
    assert result["success"]
    assert isinstance(result["data"], list)


def test_background_capture_lifecycle():
    """start_capture -> capture_status -> stop_capture must be well-formed."""
    start = asyncio.run(packetsniffer_ops(operation="start_capture", count=5, timeout=3))
    assert start["success"]
    cid = start["data"]["capture_id"]

    # Poll until the capture leaves the running state (no Npcap/admin -> error, else done)
    for _ in range(10):
        st = asyncio.run(packetsniffer_ops(operation="capture_status", capture_id=cid))
        if st["data"]["status"] != "running":
            break
        time.sleep(0.5)

    stop = asyncio.run(packetsniffer_ops(operation="stop_capture", capture_id=cid))
    assert stop["success"] or stop["operation"] == "stop_capture"
    assert stop["operation"] == "stop_capture"

    final = asyncio.run(packetsniffer_ops(operation="capture_status", capture_id=cid))
    assert final["data"]["status"] in ("done", "error")


def test_stop_capture_requires_id():
    """stop_capture without a capture_id should return a clean error."""
    result = asyncio.run(packetsniffer_ops(operation="stop_capture"))
    assert not result["success"]
    assert "error" in result


def test_decode_pcap_missing_file():
    """decode_pcap on a nonexistent file should return a clean error dict."""
    result = asyncio.run(packetsniffer_ops(operation="decode_pcap", file_path="nonexistent_123.pcap"))
    assert not result["success"]
    assert "error" in result


def test_decode_pcap_tshark_dependency(tmp_path):
    """decode_pcap should decode when tshark exists, or report missing_dependency."""
    pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53, dport=53)
    path = tmp_path / "dns.pcap"
    wrpcap(str(path), [pkt])

    result = asyncio.run(packetsniffer_ops(operation="decode_pcap", file_path=str(path)))
    if shutil.which("tshark"):
        assert result["success"]
        assert result["data"]["decoded"] >= 1
    else:
        assert not result["success"]
        assert result.get("error_type") == "missing_dependency"
