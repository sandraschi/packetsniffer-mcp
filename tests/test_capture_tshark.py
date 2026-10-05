"""Cross-check the capture decoders against Wireshark's own dissectors (skipped when tshark is not installed).

The synthetic captures are built by our own code, so on their own they only prove self-consistency. tshark
decodes the same bytes with an independent implementation: if it reads the same bus, device, endpoint, transfer
type and payload, the USBPcap header layout is right; if it identifies the same RFCOMM frame types and lengths,
the HCI/L2CAP/RFCOMM framing is right.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from packetsniffer_mcp.capture import ops
from tests.capture_builders import (
    CONTROL,
    bt_session,
    config_descriptor,
    device_descriptor,
    usb_frame,
    write_btsnoop,
    write_pcap,
    write_pcapng,
)

TSHARK = shutil.which("tshark") or (
    r"C:\Program Files\Wireshark\tshark.exe" if Path(r"C:\Program Files\Wireshark\tshark.exe").is_file() else None
)
pytestmark = pytest.mark.skipif(TSHARK is None, reason="tshark (Wireshark) is not installed")


def _tshark(path: Path, *fields: str, display_filter: str | None = None) -> list[list[str]]:
    cmd = [TSHARK, "-r", str(path), "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True)  # noqa: S603
    return [line.split("\t") for line in proc.stdout.splitlines()]


USB_FRAMES = [
    usb_frame(device=5, endpoint=0x80, transfer=CONTROL, stage=0, data=b"\x80\x06\x00\x01\x00\x00\x12\x00"),
    usb_frame(device=5, endpoint=0x80, transfer=CONTROL, stage=1, data=device_descriptor(0x0922, 0x1009)),
    usb_frame(device=5, endpoint=0x80, transfer=CONTROL, stage=1, data=config_descriptor(iface_class=7)),
    usb_frame(device=5, endpoint=0x02, data=b"\x1b\x41\x02\x00\x08"),
    usb_frame(device=5, endpoint=0x02, data=b""),
    usb_frame(device=5, endpoint=0x81, data=b"\x00\x01"),
]


@pytest.mark.parametrize("writer", [write_pcap, write_pcapng], ids=["pcap", "pcapng"])
def test_tshark_reads_our_usbpcap_frames_the_same_way(tmp_path, writer):
    path = writer(tmp_path / "usb.cap", 249, USB_FRAMES)
    rows = _tshark(
        path,
        "usb.bus_id",
        "usb.device_address",
        "usb.endpoint_address",
        "usb.transfer_type",
        "usb.capdata",
        "usb.setup.bRequest",
    )
    assert len(rows) == len(USB_FRAMES)
    for i, (row, frame) in enumerate(zip(rows, USB_FRAMES, strict=True)):
        bus, device, endpoint, transfer, capdata, request = (row + [""] * 6)[:6]
        assert (int(bus), int(device)) == (1, 5)
        if i == 0:
            # A control setup packet: tshark dissects its 8 bytes into usb.setup.* instead of capdata.
            # GET_DESCRIPTOR is request 6, the byte our frame carries at setup offset 1.
            assert capdata == "" and int(request) == frame[28 + 1]
            continue
        # tshark reports the same payload bytes our parser extracts
        header_len = 28 if int(transfer, 16) == CONTROL else 27
        assert capdata.replace(":", "") == frame[header_len:].hex()

    ours = ops.usb_payloads(str(path), direction="both")["data"]["transfers"]
    bulk = [r for r in rows if int(r[3], 16) == 3 and r[4]]
    assert [t["hex"].replace(" ", "") for t in ours] == [r[4] for r in bulk]
    assert [t["endpoint"] for t in ours] == [r[2] for r in bulk]


def test_tshark_confirms_the_descriptor_bytes_we_parse(tmp_path):
    path = write_pcap(tmp_path / "usb.pcap", 249, USB_FRAMES)
    rows = _tshark(path, "usb.idVendor", "usb.idProduct", "usb.bInterfaceClass", display_filter="usb.idVendor")
    # Not every Wireshark build dissects descriptors from USBPcap control data; only assert when it does.
    if rows:
        assert rows[0][0] in ("0x0922", "0x00000922")
    device = ops.usb_payloads(str(path), direction="both", transfer_types="control")["data"]["devices"][0]
    assert (device["vendor_id"], device["product_id"], device["interfaces"][0]["class_name"]) == (
        "0922",
        "1009",
        "printer",
    )


def test_tshark_identifies_the_same_rfcomm_frames_and_lengths(tmp_path):
    packets = bt_session([b"\x1b\x41\x01", b"HELLO"], [b"\x00\x10"])
    path = write_btsnoop(tmp_path / "bt.log", packets)
    rows = _tshark(
        path, "frame.protocols", "btrfcomm.frame_type", "btrfcomm.dlci", "data.len", display_filter="btrfcomm"
    )
    types = [r[1] for r in rows]
    assert types == ["0x2f", "0x63", "0xef", "0xef", "0xef"]  # SABM, UA, then three UIH
    assert [int(r[2], 16) if r[2].startswith("0x") else int(r[2]) for r in rows[2:]] == [2, 2, 2]
    assert [r[3] for r in rows[2:]] == ["3", "5", "2"]

    ours = ops.btsnoop_payloads(str(path), direction="both")["data"]["payloads"]
    assert [p["length"] for p in ours] == [3, 5, 2]
    assert all(p["dlci"] == 2 for p in ours)


def test_tshark_reads_the_same_rfcomm_checksums_as_our_fcs_function(tmp_path):
    path = write_btsnoop(tmp_path / "bt.log", bt_session([b"x"]))
    rows = _tshark(path, "btrfcomm.frame_type", "btrfcomm.fcs", display_filter="btrfcomm")
    assert rows[0] == ["0x2f", "0x1c"] and rows[1] == ["0x63", "0xd7"]  # SABM and UA on DLCI 0
