"""Builders for synthetic USBPcap / pcapng / btsnoop files used by the capture tests."""

from __future__ import annotations

import struct
from pathlib import Path

from packetsniffer_mcp.capture.btsnoop import rfcomm_fcs

# --- generic containers ---------------------------------------------------------------------


def write_pcap(path: Path, linktype: int, frames: list[bytes], *, start: float = 1000.0, step: float = 0.01) -> Path:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for i, frame in enumerate(frames):
        ts = start + i * step
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame
    path.write_bytes(bytes(out))
    return path


def _block(btype: int, body: bytes) -> bytes:
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total)


def write_pcapng(path: Path, linktype: int, frames: list[bytes], *, start: float = 1000.0, step: float = 0.01) -> Path:
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    idb = struct.pack("<HHI", linktype, 0, 65535) + struct.pack("<HHB3x", 9, 1, 6) + struct.pack("<HH", 0, 0)  # 1 us
    out = _block(0x0A0D0D0A, shb) + _block(1, idb)
    for i, frame in enumerate(frames):
        ticks = int((start + i * step) * 1_000_000)
        body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame
        out += _block(6, body)
    path.write_bytes(out)
    return path


# --- USBPcap --------------------------------------------------------------------------------

BULK, INTERRUPT, CONTROL = 3, 1, 2


def usb_frame(
    *, device: int, endpoint: int, transfer: int = BULK, data: bytes = b"", stage: int | None = None, bus: int = 1
) -> bytes:
    header_len = 28 if transfer == CONTROL else 27
    head = struct.pack("<HQIHBHHBBI", header_len, 1, 0, 0x0009, 0, bus, device, endpoint, transfer, len(data))
    if transfer == CONTROL:
        head += bytes([stage or 0])
    return head + data


def device_descriptor(vid: int, pid: int, dev_class: int = 0) -> bytes:
    return struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, dev_class, 0, 0, 64, vid, pid, 0x0100, 1, 2, 3, 1)


def config_descriptor(*, iface_class: int = 7) -> bytes:
    iface = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 2, iface_class, 1, 2, 0)
    ep_out = struct.pack("<BBBBHB", 7, 5, 0x02, 2, 64, 0)
    ep_in = struct.pack("<BBBBHB", 7, 5, 0x81, 2, 64, 0)
    body = iface + ep_out + ep_in
    return struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), 1, 1, 0, 0x80, 50) + body


# --- Bluetooth ------------------------------------------------------------------------------

BTSNOOP_EPOCH_US = 0x00DCDDB30F2F8000


def acl(handle: int, payload: bytes, *, pb: int = 0b10) -> bytes:
    """H4 ACL packet (type 2)."""
    return b"\x02" + struct.pack("<HH", handle | (pb << 12), len(payload)) + payload


def l2cap(cid: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload), cid) + payload


def l2cap_conn_req(ident: int, psm: int, scid: int) -> bytes:
    return l2cap(1, struct.pack("<BBHHH", 2, ident, 4, psm, scid))


def l2cap_conn_rsp(ident: int, dcid: int, scid: int, result: int = 0) -> bytes:
    return l2cap(1, struct.pack("<BBHHHHH", 3, ident, 8, dcid, scid, result, 0))


def rfcomm_uih(dlci: int, data: bytes, *, credit: int | None = None, length_includes_credit: bool = False) -> bytes:
    """RFCOMM UIH frame (command direction bit set in the address)."""
    addr = (dlci << 2) | 0x03
    control = 0xFF if credit is not None else 0xEF
    length = len(data) + (1 if credit is not None and length_includes_credit else 0)
    length_field = bytes([(length << 1) | 1]) if length < 128 else bytes([(length & 0x7F) << 1, length >> 7])
    frame = bytes([addr, control]) + length_field
    if credit is not None:
        frame += bytes([credit])
    frame += data
    return frame + bytes([rfcomm_fcs(bytes([addr, control]))])


def rfcomm_control(dlci: int, control: int) -> bytes:
    """SABM / UA / DISC frame (no data)."""
    addr = (dlci << 2) | 0x03
    return bytes([addr, control, 0x01]) + bytes([rfcomm_fcs(bytes([addr, control, 0x01]))])


def write_btsnoop(path: Path, packets: list[tuple[bytes, str]], *, datalink: int = 1002) -> Path:
    """``packets`` are ``(h4_bytes, 'tx'|'rx')``. For datalink 1001 the type byte is stripped."""
    out = bytearray(b"btsnoop\x00" + struct.pack(">II", 1, datalink))
    for i, (h4, direction) in enumerate(packets):
        flags = 1 if direction == "rx" else 0
        data = h4
        if datalink == 1001:
            flags |= 0 if h4[0] == 2 else 2
            data = h4[1:]
        ts = BTSNOOP_EPOCH_US + int((1000.0 + i * 0.01) * 1_000_000)
        out += struct.pack(">IIIIq", len(data), len(data), flags, 0, ts) + data
    path.write_bytes(bytes(out))
    return path


def bt_session(payloads_tx: list[bytes], payloads_rx: list[bytes] | None = None, *, handle: int = 0x0041):
    """A full RFCOMM-over-L2CAP session: connect, then data. Returns ``(h4_bytes, direction)`` packets."""
    local, remote = 0x0040, 0x0041
    pkts = [
        (acl(handle, l2cap_conn_req(7, 3, local)), "tx"),
        (acl(handle, l2cap_conn_rsp(7, remote, local)), "rx"),
        (acl(handle, l2cap(remote, rfcomm_control(0, 0x3F))), "tx"),  # SABM on DLCI 0
        (acl(handle, l2cap(local, rfcomm_control(0, 0x73))), "rx"),  # UA
    ]
    for payload in payloads_tx:
        pkts.append((acl(handle, l2cap(remote, rfcomm_uih(2, payload))), "tx"))
    for payload in payloads_rx or []:
        pkts.append((acl(handle, l2cap(local, rfcomm_uih(2, payload))), "rx"))
    return pkts
