"""Capture analysis: file readers, USBPcap payloads, Bluetooth RFCOMM, diffing.

All captures are synthetic (built in tests/capture_builders.py). The USBPcap header layout is the one scapy
defines; RFCOMM FCS values are the well-known ones for SABM/UA on DLCI 0. None of this was checked against a
capture from real hardware.
"""

import struct

import pytest

from packetsniffer_mcp.capture import ops
from packetsniffer_mcp.capture.btsnoop import extract_payloads, rfcomm_fcs
from packetsniffer_mcp.capture.diff import diff_streams, diff_transfers
from packetsniffer_mcp.capture.pcapfile import CaptureFormatError, read_records
from packetsniffer_mcp.capture.usbpcap import describe_devices, load_usb_capture
from tests.capture_builders import (
    CONTROL,
    INTERRUPT,
    acl,
    bt_session,
    config_descriptor,
    device_descriptor,
    l2cap,
    l2cap_conn_req,
    l2cap_conn_rsp,
    rfcomm_control,
    rfcomm_uih,
    usb_frame,
    write_btsnoop,
    write_pcap,
    write_pcapng,
)

USBPCAP, H4, H4_PHDR = 249, 187, 201

# --- readers ----------------------------------------------------------------------------------


def test_pcap_and_pcapng_give_the_same_records(tmp_path):
    frames = [usb_frame(device=2, endpoint=0x02, data=b"\x01\x02"), usb_frame(device=2, endpoint=0x02, data=b"\x03")]
    fmt1, r1 = read_records(write_pcap(tmp_path / "a.pcap", USBPCAP, frames))
    fmt2, r2 = read_records(write_pcapng(tmp_path / "a.pcapng", USBPCAP, frames))
    assert (fmt1, fmt2) == ("pcap", "pcapng")
    assert [r.data for r in r1] == [r.data for r in r2] == frames
    assert r2[1].ts - r2[0].ts == pytest.approx(0.01, abs=1e-5)
    assert all(r.linktype == USBPCAP for r in r1 + r2)


def test_truncated_and_unknown_files_raise_instead_of_returning_short_results(tmp_path):
    good = write_pcap(tmp_path / "g.pcap", USBPCAP, [usb_frame(device=2, endpoint=2, data=b"abc")]).read_bytes()
    (tmp_path / "cut.pcap").write_bytes(good[:-2])
    with pytest.raises(CaptureFormatError, match="truncated"):
        read_records(tmp_path / "cut.pcap")
    (tmp_path / "junk.bin").write_bytes(b"not a capture at all")
    with pytest.raises(CaptureFormatError, match="unrecognised"):
        read_records(tmp_path / "junk.bin")
    with pytest.raises(CaptureFormatError, match="does not exist"):
        read_records(tmp_path / "missing.pcap")


# --- USB --------------------------------------------------------------------------------------


def _label_capture(tmp_path, name, out_data: bytes):
    """One device, a bulk OUT submission carrying data, its empty completion, and a status reply on IN."""
    frames = [
        usb_frame(device=2, endpoint=0x02, data=out_data),
        usb_frame(device=2, endpoint=0x02, data=b""),  # completion of the OUT URB: no data
        usb_frame(device=2, endpoint=0x81, data=b""),  # IN submission: no data yet
        usb_frame(device=2, endpoint=0x81, data=b"\x00\x01"),  # IN completion with the status
    ]
    return str(write_pcap(tmp_path / name, USBPCAP, frames))


def test_usb_payloads_returns_each_out_transfer_once(tmp_path):
    path = _label_capture(tmp_path, "a.pcap", b"\x1b\x41\x02")
    result = ops.usb_payloads(path)
    assert result["success"]
    data = result["data"]
    assert data["selected"] == 1 and data["transfers"][0]["hex"] == "1b 41 02"
    assert data["transfers"][0]["direction"] == "out" and data["transfers"][0]["endpoint"] == "0x02"
    assert data["stream"]["length"] == 3


def test_usb_payloads_direction_in_and_both(tmp_path):
    path = _label_capture(tmp_path, "a.pcap", b"\xaa")
    assert [t["hex"] for t in ops.usb_payloads(path, direction="in")["data"]["transfers"]] == ["00 01"]
    both = ops.usb_payloads(path, direction="both")["data"]
    assert both["selected"] == 2
    assert {e["direction"] for e in both["endpoints"]} == {"in", "out"}


def test_usb_payloads_filters_device_endpoint_and_transfer_type(tmp_path):
    frames = [
        usb_frame(device=2, endpoint=0x02, data=b"a"),
        usb_frame(device=3, endpoint=0x02, data=b"b"),
        usb_frame(device=2, endpoint=0x04, data=b"c"),
        usb_frame(device=2, endpoint=0x03, transfer=INTERRUPT, data=b"d"),
    ]
    path = str(write_pcap(tmp_path / "f.pcap", USBPCAP, frames))
    hexes = lambda **kw: [t["hex"] for t in ops.usb_payloads(path, **kw)["data"]["transfers"]]  # noqa: E731
    assert hexes() == ["61", "62", "63", "64"]  # bulk + interrupt by default
    assert hexes(device=2) == ["61", "63", "64"]
    assert hexes(endpoint=2) == ["61", "62"]
    assert hexes(transfer_types="interrupt") == ["64"]


def test_usb_payloads_truncates_hex_and_exports_the_full_stream(tmp_path):
    payload = bytes(range(200))
    path = _label_capture(tmp_path, "a.pcap", payload)
    out = tmp_path / "stream.bin"
    result = ops.usb_payloads(path, max_bytes=16, export_path=str(out))
    t = result["data"]["transfers"][0]
    assert t["truncated"] is True and t["length"] == 200 and len(t["hex"].split()) == 16
    assert out.read_bytes() == payload
    assert result["data"]["exported_to"] == str(out)


def test_usb_export_rejects_dangerous_suffixes(tmp_path):
    path = _label_capture(tmp_path, "a.pcap", b"x")
    result = ops.usb_payloads(path, export_path=str(tmp_path / "evil.ps1"))
    assert not result["success"] and result["error_type"] == "invalid_request"


def test_usb_control_setup_is_out_and_descriptors_identify_a_printer_class_device(tmp_path):
    frames = [
        usb_frame(
            device=5, endpoint=0x80, transfer=CONTROL, stage=0, data=b"\x80\x06\x00\x01\x00\x00\x12\x00"
        ),  # setup
        usb_frame(device=5, endpoint=0x80, transfer=CONTROL, stage=1, data=device_descriptor(0x0922, 0x1009)),
        usb_frame(device=5, endpoint=0x80, transfer=CONTROL, stage=1, data=config_descriptor(iface_class=7)),
        usb_frame(device=5, endpoint=0x80, transfer=CONTROL, stage=1, data=config_descriptor(iface_class=7)),  # re-read
    ]
    path = str(write_pcap(tmp_path / "enum.pcap", USBPCAP, frames))
    devices = ops.usb_payloads(path, direction="both", transfer_types="control")["data"]["devices"]
    assert len(devices) == 1
    dev = devices[0]
    assert (dev["vendor_id"], dev["product_id"]) == ("0922", "1009")
    assert len(dev["interfaces"]) == 1, "a repeated config descriptor must not duplicate interfaces"
    iface = dev["interfaces"][0]
    assert iface["class_name"] == "printer"
    assert [(e["address"], e["direction"], e["type"]) for e in iface["endpoints"]] == [
        ("0x02", "out", "bulk"),
        ("0x81", "in", "bulk"),
    ]
    setup = [t for t in load_usb_capture(path) if t.stage == 0]
    assert setup and setup[0].direction == "out"


def test_describe_devices_ignores_captures_without_enumeration(tmp_path):
    path = _label_capture(tmp_path, "a.pcap", b"x")
    assert describe_devices(load_usb_capture(path)) == []
    assert ops.usb_payloads(path)["data"]["devices"] == []


def test_non_usb_capture_is_rejected_with_a_clear_error(tmp_path):
    path = str(write_pcap(tmp_path / "eth.pcap", 1, [b"\x00" * 60]))
    result = ops.usb_payloads(path)
    assert not result["success"] and result["error_type"] == "invalid_capture" and "USBPcap" in result["error"]


def test_usb_payloads_missing_file_and_bad_arguments(tmp_path):
    assert ops.usb_payloads(None)["error_type"] == "invalid_request"
    assert ops.usb_payloads(str(tmp_path / "nope.pcap"))["error_type"] == "invalid_capture"
    path = _label_capture(tmp_path, "a.pcap", b"x")
    assert ops.usb_payloads(path, direction="sideways")["error_type"] == "invalid_request"
    assert ops.usb_payloads(path, transfer_types="warp")["error_type"] == "invalid_request"


# --- Bluetooth --------------------------------------------------------------------------------


def test_rfcomm_fcs_matches_the_well_known_dlci0_frames():
    assert rfcomm_fcs(bytes([0x03, 0x3F, 0x01])) == 0x1C  # SABM, DLCI 0
    assert rfcomm_fcs(bytes([0x03, 0x73, 0x01])) == 0xD7  # UA, DLCI 0


def test_btsnoop_extracts_rfcomm_data_by_direction(tmp_path):
    packets = bt_session([b"\x1b\x41\x01", b"\x1b\x42"], [b"\x00\x10"])
    path = str(write_btsnoop(tmp_path / "bt.log", packets))
    tx = ops.btsnoop_payloads(path)["data"]
    assert [p["hex"] for p in tx["payloads"]] == ["1b 41 01", "1b 42"]
    assert all(p["psm"] == 3 and p["dlci"] == 2 and p["fcs_ok"] is True for p in tx["payloads"])
    assert [p["hex"] for p in ops.btsnoop_payloads(path, direction="rx")["data"]["payloads"]] == ["00 10"]
    both = ops.btsnoop_payloads(path, direction="both")["data"]
    assert both["selected"] == 3 and both["stream"]["length"] == 7


def test_connection_management_and_empty_frames_are_not_payloads(tmp_path):
    handle = 0x41
    packets = bt_session([])
    packets.append((acl(handle, l2cap(0x41, rfcomm_uih(2, b""))), "tx"))  # empty keep-alive UIH
    packets.append((acl(handle, l2cap(0x41, rfcomm_uih(0, b"\x01\x02"))), "tx"))  # DLCI 0 control channel
    path = str(write_btsnoop(tmp_path / "bt.log", packets))
    data = ops.btsnoop_payloads(path, direction="both")["data"]
    assert data["selected"] == 0 and data["notes"], "an empty result must explain itself"


@pytest.mark.parametrize("includes_credit", [False, True])
def test_credit_based_flow_control_byte_is_not_user_data(tmp_path, includes_credit):
    handle, local, remote = 0x41, 0x40, 0x41
    frame = rfcomm_uih(2, b"\xde\xad\xbe\xef", credit=9, length_includes_credit=includes_credit)
    packets = [
        (acl(handle, l2cap_conn_req(1, 3, local)), "tx"),
        (acl(handle, l2cap_conn_rsp(1, remote, local)), "rx"),
        (acl(handle, l2cap(remote, frame)), "tx"),
    ]
    path = str(write_btsnoop(tmp_path / "bt.log", packets))
    assert [p["hex"] for p in ops.btsnoop_payloads(path)["data"]["payloads"]] == ["de ad be ef"]


def test_fragmented_acl_is_reassembled(tmp_path):
    handle, local, remote = 0x41, 0x40, 0x41
    pdu = l2cap(remote, rfcomm_uih(2, bytes(range(100))))
    packets = [
        (acl(handle, l2cap_conn_req(1, 3, local)), "tx"),
        (acl(handle, l2cap_conn_rsp(1, remote, local)), "rx"),
        (acl(handle, pdu[:40], pb=0b10), "tx"),
        (acl(handle, pdu[40:], pb=0b01), "tx"),
    ]
    path = str(write_btsnoop(tmp_path / "bt.log", packets))
    payloads = ops.btsnoop_payloads(path)["data"]["payloads"]
    assert len(payloads) == 1 and payloads[0]["length"] == 100


def test_other_psms_are_ignored(tmp_path):
    handle, local, remote = 0x41, 0x40, 0x41
    packets = [
        (acl(handle, l2cap_conn_req(1, 0x19, local)), "tx"),  # AVDTP, not RFCOMM
        (acl(handle, l2cap_conn_rsp(1, remote, local)), "rx"),
        (acl(handle, l2cap(remote, rfcomm_uih(2, b"audio"))), "tx"),
    ]
    path = str(write_btsnoop(tmp_path / "bt.log", packets))
    assert ops.btsnoop_payloads(path, direction="both")["data"]["selected"] == 0


def test_unknown_channel_is_accepted_only_when_the_fcs_verifies(tmp_path):
    handle = 0x41
    good = rfcomm_uih(2, b"hello")
    bad = good[:-1] + bytes([good[-1] ^ 0xFF])
    packets = [(acl(handle, l2cap(0x41, good)), "tx"), (acl(handle, l2cap(0x41, bad)), "tx")]
    path = str(write_btsnoop(tmp_path / "late.log", packets))
    payloads = ops.btsnoop_payloads(path)["data"]["payloads"]
    assert [p["hex"] for p in payloads] == ["68 65 6c 6c 6f"] and payloads[0]["psm"] is None


def test_btsnoop_unencapsulated_datalink_and_pcap_h4_with_direction(tmp_path):
    session = bt_session([b"\x01\x02\x03"])
    p1001 = str(write_btsnoop(tmp_path / "u.log", session, datalink=1001))
    assert [p["hex"] for p in ops.btsnoop_payloads(p1001)["data"]["payloads"]] == ["01 02 03"]

    frames = [struct.pack(">I", 1 if d == "rx" else 0) + h4 for h4, d in session]
    p201 = str(write_pcapng(tmp_path / "wireshark.pcapng", H4_PHDR, frames))
    assert [p["hex"] for p in ops.btsnoop_payloads(p201)["data"]["payloads"]] == ["01 02 03"]

    p187 = str(write_pcap(tmp_path / "nodir.pcap", H4, [h4 for h4, _ in session]))
    result = ops.btsnoop_payloads(p187)  # no direction flag in this format
    assert result["data"]["selected"] == 0 and any("direction" in n for n in result["data"]["notes"])
    assert ops.btsnoop_payloads(p187, direction="both")["data"]["selected"] == 1


def test_commands_and_events_are_skipped_and_wrong_link_types_rejected(tmp_path):
    packets = [(b"\x01\x03\x0c\x00", "tx"), (b"\x04\x0e\x04\x01\x03\x0c\x00", "rx"), *bt_session([b"x"])]
    path = str(write_btsnoop(tmp_path / "mix.log", packets))
    assert ops.btsnoop_payloads(path)["data"]["selected"] == 1
    usb = str(write_pcap(tmp_path / "u.pcap", USBPCAP, [usb_frame(device=2, endpoint=2, data=b"x")]))
    result = ops.btsnoop_payloads(usb)
    assert not result["success"] and "Bluetooth HCI" in result["error"]


def test_extract_payloads_handles_a_peer_initiated_connection(tmp_path):
    handle, peer_cid, our_cid = 0x41, 0x50, 0x41
    packets = [
        (acl(handle, l2cap_conn_req(3, 3, peer_cid)), "rx"),  # the printer's side connects to us
        (acl(handle, l2cap_conn_rsp(3, our_cid, peer_cid)), "tx"),
        (acl(handle, l2cap(peer_cid, rfcomm_uih(4, b"from-host"))), "tx"),
    ]
    path = tmp_path / "peer.log"
    write_btsnoop(path, packets)
    _fmt, records = read_records(path)
    out = extract_payloads(records)
    assert [(p.data, p.psm, p.dlci) for p in out] == [(b"from-host", 3, 4)]
    _ = rfcomm_control  # imported for symmetry with the other tests


# --- diff -------------------------------------------------------------------------------------


def test_diff_identical_and_equal_length_ranges():
    assert diff_streams(b"abc", b"abc")["identical"] is True
    d = diff_streams(bytes([1, 2, 3, 4, 5, 6]), bytes([1, 2, 9, 9, 5, 7]))
    assert d["changed_bytes"] == 3
    assert [(r["offset"], r["length"]) for r in d["ranges"]] == [(2, 2), (5, 1)]
    assert d["ranges"][0]["a"] == "03 04" and d["ranges"][0]["b"] == "09 09"


def test_diff_different_lengths_reports_prefix_suffix_and_middle():
    a = b"HEAD" + b"\x00" * 4 + b"TAIL"
    b = b"HEAD" + b"\xff" * 10 + b"TAIL"
    d = diff_streams(a, b)
    assert (d["common_prefix"], d["common_suffix"]) == (4, 4)
    assert d["middle"]["length_a"] == 4 and d["middle"]["length_b"] == 10 and "ranges" not in d


def test_diff_transfers_reports_missing_and_changed_transfers():
    d = diff_transfers([b"a", b"b", b"c"], [b"a", b"X"])
    assert d["differing"] == 2
    assert [(i["transfer"], i["length_a"], i["length_b"]) for i in d["items"]] == [(1, 1, 1), (2, 1, None)]


def test_diff_captures_finds_the_byte_that_encodes_the_dot(tmp_path):
    header = b"\x1b\x41\x0c"
    blank = _label_capture(tmp_path, "01-blank.pcap", header + b"\x00\x00\x00\x00")
    dot = _label_capture(tmp_path, "02-dot.pcap", header + b"\x00\x08\x00\x00")
    result = ops.diff_captures(blank, dot)
    assert result["success"] and result["data"]["kind"] == "usb"
    ranges = result["data"]["stream"]["ranges"]
    assert [(r["offset"], r["a"], r["b"]) for r in ranges] == [(4, "00", "08")]
    assert result["data"]["transfers"]["differing"] == 1


def test_diff_captures_works_on_bluetooth_and_rejects_mixed_kinds(tmp_path):
    a = str(write_btsnoop(tmp_path / "a.log", bt_session([b"\x01\x00"])))
    b = str(write_btsnoop(tmp_path / "b.log", bt_session([b"\x01\x80"])))
    result = ops.diff_captures(a, b, direction="tx")
    assert result["data"]["kind"] == "bluetooth" and result["data"]["stream"]["changed_bytes"] == 1
    usb = _label_capture(tmp_path, "u.pcap", b"x")
    mixed = ops.diff_captures(a, usb)
    assert not mixed["success"] and mixed["error_type"] == "invalid_request"


def test_diff_captures_requires_both_files():
    assert ops.diff_captures("a.pcap", None)["error_type"] == "invalid_request"
