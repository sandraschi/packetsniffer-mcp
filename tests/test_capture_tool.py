"""The capture operations through the real MCP tool surface (schema validation included)."""

import pytest
from fastmcp import Client

from packetsniffer_mcp.mcp_instance import get_mcp
from packetsniffer_mcp.tools import sniffer_tools  # noqa: F401  (registers packetsniffer_ops)
from tests.capture_builders import bt_session, usb_frame, write_btsnoop, write_pcap

ALL_OPERATIONS = {
    "list_interfaces",
    "sniff",
    "start_capture",
    "capture_status",
    "stop_capture",
    "decode_pcap",
    "analyze_pcap",
    "usb_list_hubs",
    "usb_capture",
    "usb_payloads",
    "btsnoop_payloads",
    "diff_captures",
}


async def _call(**args):
    async with Client(get_mcp()) as client:
        result = await client.call_tool("packetsniffer_ops", args, raise_on_error=False)
        return result.structured_content or result.data


async def test_schema_advertises_every_operation_the_tool_dispatches():
    # Regression: the Literal used to list only three operations, so MCP clients could not call the rest.
    async with Client(get_mcp()) as client:
        tool = next(t for t in await client.list_tools() if t.name == "packetsniffer_ops")
    schema = tool.inputSchema["properties"]["operation"]
    enum = set(schema.get("enum") or [v for branch in schema.get("anyOf", []) for v in branch.get("enum", [])])
    assert enum == ALL_OPERATIONS


async def test_usb_payloads_through_the_mcp_client(tmp_path):
    path = write_pcap(tmp_path / "a.pcap", 249, [usb_frame(device=2, endpoint=0x02, data=b"\x1b\x41\x02")])
    out = await _call(operation="usb_payloads", file_path=str(path))
    assert out["success"] and out["data"]["transfers"][0]["hex"] == "1b 41 02"


async def test_btsnoop_payloads_default_direction_works_for_bluetooth_callers(tmp_path):
    path = write_btsnoop(tmp_path / "bt.log", bt_session([b"\x01\x02"]))
    out = await _call(operation="btsnoop_payloads", file_path=str(path))  # 'direction' left at its USB default
    assert out["success"] and out["data"]["selected"] == 1


async def test_diff_captures_through_the_mcp_client(tmp_path):
    a = write_pcap(tmp_path / "a.pcap", 249, [usb_frame(device=2, endpoint=2, data=b"\x00\x00")])
    b = write_pcap(tmp_path / "b.pcap", 249, [usb_frame(device=2, endpoint=2, data=b"\x00\x01")])
    out = await _call(operation="diff_captures", file_path=str(a), file_path_b=str(b))
    assert out["success"] and out["data"]["stream"]["changed_bytes"] == 1


@pytest.mark.parametrize("operation", ["usb_payloads", "btsnoop_payloads"])
async def test_missing_file_is_a_structured_error(operation):
    out = await _call(operation=operation, file_path="does-not-exist.pcap")
    assert out["success"] is False and out["error_type"] == "invalid_capture"
