"""USBPcap capture analysis: per-transfer payloads and device/interface descriptors.

USBPcap records one packet per URB phase. A bulk or interrupt OUT URB carries its data in the submission
(device direction bit clear on the endpoint) and an empty completion; an IN URB is the reverse. Reporting only
packets that carry data therefore gives each transfer exactly once, in the direction the data travelled.

Header layout (little endian, ``USBPCAP_BUFFER_PACKET_HEADER``), cross-checked against scapy's definition:
``u16 headerLen, u64 irpId, u32 status, u16 function, u8 info, u16 bus, u16 device, u8 endpoint,
u8 transfer, u32 dataLength`` = 27 bytes; control transfers add a ``u8 stage`` (0 setup, 1 data, 2 status).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from .pcapfile import LINKTYPE_USBPCAP, CaptureFormatError, Record, read_records

TRANSFER_NAMES = {0: "isochronous", 1: "interrupt", 2: "control", 3: "bulk"}
_NAME_TO_TRANSFER = {v: k for k, v in TRANSFER_NAMES.items()}
# bmAttributes bits 1..0 of an endpoint descriptor use the USB spec's numbering, which differs from USBPcap's.
_ENDPOINT_TYPES = ("control", "isochronous", "bulk", "interrupt")
_BASE_HEADER = 27

USB_CLASS_NAMES = {
    0x01: "audio",
    0x02: "cdc-communications",
    0x03: "hid",
    0x07: "printer",
    0x08: "mass-storage",
    0x09: "hub",
    0x0A: "cdc-data",
    0xE0: "wireless-controller",
    0xFF: "vendor-specific",
}


@dataclass(frozen=True)
class UsbTransfer:
    index: int
    ts: float
    bus: int
    device: int
    endpoint: int
    direction: str  # "out" = host to device, "in" = device to host
    transfer: str
    stage: int | None
    data: bytes


def parse_usbpcap(records: list[Record]) -> list[UsbTransfer]:
    """Turn USBPcap records into transfers that carry data. Raises if the capture is not USBPcap."""
    if records and any(r.linktype != LINKTYPE_USBPCAP for r in records):
        raise CaptureFormatError(
            "this is not a USBPcap capture (link type is not 249); capture USB with USBPcap, not an Ethernet interface"
        )
    out: list[UsbTransfer] = []
    for i, rec in enumerate(records):
        raw = rec.data
        if len(raw) < _BASE_HEADER:
            continue
        header_len, _irp, _status, _function, _info, bus, device, endpoint, transfer, data_len = struct.unpack_from(
            "<HQIHBHHBBI", raw, 0
        )
        if header_len < _BASE_HEADER or header_len > len(raw):
            raise CaptureFormatError(f"record {i}: USBPcap header length {header_len} is invalid")
        stage = raw[_BASE_HEADER] if transfer == 2 and header_len > _BASE_HEADER else None
        data = raw[header_len : header_len + data_len]
        if not data:
            continue
        out.append(
            UsbTransfer(
                index=i,
                ts=rec.ts,
                bus=bus,
                device=device,
                endpoint=endpoint,
                direction="in" if endpoint & 0x80 else "out",
                transfer=TRANSFER_NAMES.get(transfer, f"unknown-{transfer}"),
                stage=stage,
                data=data,
            )
        )
    # A control setup stage (host to device) is always OUT; its direction bit says nothing about the data stage.
    return [
        UsbTransfer(**{**t.__dict__, "direction": "out"}) if t.transfer == "control" and t.stage == 0 else t
        for t in out
    ]


def filter_transfers(
    transfers: list[UsbTransfer],
    *,
    direction: str = "out",
    device: int | None = None,
    endpoint: int | None = None,
    transfer_types: tuple[str, ...] = ("bulk", "interrupt"),
) -> list[UsbTransfer]:
    """Select transfers by direction ("out", "in", "both"), device address, endpoint and transfer type."""
    keep = []
    for t in transfers:
        if direction != "both" and t.direction != direction:
            continue
        if device is not None and t.device != device:
            continue
        if endpoint is not None and (t.endpoint & 0x7F) != (endpoint & 0x7F):
            continue
        if transfer_types and t.transfer not in transfer_types:
            continue
        keep.append(t)
    return keep


def describe_devices(transfers: list[UsbTransfer]) -> list[dict[str, Any]]:
    """Recover VID/PID and interface classes from captured GET_DESCRIPTOR replies.

    Only present when the capture includes enumeration (start the capture before plugging the device in, or use
    inject-descriptors). Answers "is this printer-class, HID, or vendor-specific?".
    """
    devices: dict[tuple[int, int], dict[str, Any]] = {}
    for t in transfers:
        if t.transfer != "control" or t.direction != "in" or t.stage not in (1, None):
            continue
        key = (t.bus, t.device)
        entry = devices.setdefault(key, {"bus": t.bus, "device": t.device, "interfaces": []})
        data = t.data
        if len(data) >= 18 and data[0] == 18 and data[1] == 1:
            vid, pid = struct.unpack_from("<HH", data, 8)
            entry.update(
                {
                    "vendor_id": f"{vid:04x}",
                    "product_id": f"{pid:04x}",
                    "usb_version": f"{data[3]:x}.{data[2]:02x}",
                    "device_class": data[4],
                    "max_packet_size_ep0": data[7],
                }
            )
        elif len(data) >= 9 and data[1] == 2:
            _parse_config_descriptor(data, entry)
    return [d for d in devices.values() if len(d) > 3 or d["interfaces"]]


def _parse_config_descriptor(data: bytes, entry: dict[str, Any]) -> None:
    off, iface = 0, None
    while off + 2 <= len(data):
        length, dtype = data[off], data[off + 1]
        if length < 2 or off + length > len(data):
            break
        if dtype == 4 and length >= 9:
            number, alt, n_eps, cls, sub, proto = struct.unpack_from("<BBBBBB", data, off + 2)
            seen = any(i["number"] == number and i["alt"] == alt for i in entry["interfaces"])
            # The host usually reads the configuration descriptor more than once; keep the first copy only.
            iface = (
                None
                if seen
                else {
                    "number": number,
                    "alt": alt,
                    "class": cls,
                    "class_name": USB_CLASS_NAMES.get(cls, f"0x{cls:02x}"),
                    "subclass": sub,
                    "protocol": proto,
                    "endpoints": [],
                }
            )
            if iface is not None:
                entry["interfaces"].append(iface)
        elif dtype == 5 and length >= 7 and iface is not None:
            addr, attrs, max_packet = struct.unpack_from("<BBH", data, off + 2)
            iface["endpoints"].append(
                {
                    "address": f"0x{addr:02x}",
                    "direction": "in" if addr & 0x80 else "out",
                    "type": _ENDPOINT_TYPES[attrs & 3],
                    "max_packet": max_packet,
                }
            )
        off += length


def load_usb_capture(path: str) -> list[UsbTransfer]:
    """Read a USBPcap capture file (pcap or pcapng) into data-carrying transfers."""
    _fmt, records = read_records(path)
    if not records:
        raise CaptureFormatError("the capture contains no packets")
    return parse_usbpcap(records)


def transfer_type_names(requested: str | None) -> tuple[str, ...]:
    """Parse a comma list like ``"bulk,interrupt"``; unknown names raise."""
    if not requested:
        return ("bulk", "interrupt")
    names = tuple(n.strip().lower() for n in requested.split(",") if n.strip())
    bad = [n for n in names if n not in _NAME_TO_TRANSFER]
    if bad:
        raise ValueError(f"unknown transfer type(s) {bad}; use any of {sorted(_NAME_TO_TRANSFER)}")
    return names
