"""Minimal readers for classic pcap, pcapng and btsnoop files.

Only what payload extraction needs: ``(link type, timestamp, bytes)`` per record, plus the btsnoop
direction flag. Corrupt or truncated files raise :class:`CaptureFormatError` instead of returning a
silently short result.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

LINKTYPE_BLUETOOTH_HCI_H4 = 187
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
LINKTYPE_USBPCAP = 249

BTSNOOP_DATALINK_HCI_UNENCAPSULATED = 1001
BTSNOOP_DATALINK_HCI_H4 = 1002

# btsnoop timestamps count microseconds from year 0; this is the offset to the Unix epoch.
_BTSNOOP_EPOCH_OFFSET_US = 0x00DCDDB30F2F8000

MAX_FILE_BYTES = int(os.getenv("PACKETSNIFFER_MCP_MAX_CAPTURE_BYTES", str(256 * 1024 * 1024)))

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


class CaptureFormatError(ValueError):
    """The file is not a readable capture of a supported format."""


@dataclass(frozen=True)
class Record:
    """One captured frame."""

    linktype: int
    ts: float
    data: bytes
    meta: dict = field(default_factory=dict)


def read_records(path: str | Path) -> tuple[str, list[Record]]:
    """Read every record of a pcap, pcapng or btsnoop file. Returns ``(format_name, records)``."""
    p = Path(path)
    if not p.is_file():
        raise CaptureFormatError(f"file does not exist: {p}")
    size = p.stat().st_size
    if size > MAX_FILE_BYTES:
        raise CaptureFormatError(
            f"capture is {size} bytes, over the {MAX_FILE_BYTES} limit (PACKETSNIFFER_MCP_MAX_CAPTURE_BYTES)"
        )
    raw = p.read_bytes()
    if raw[:8] == b"btsnoop\x00":
        return "btsnoop", _read_btsnoop(raw)
    if raw[:4] in _PCAP_MAGICS:
        return "pcap", _read_pcap(raw)
    if raw[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng", _read_pcapng(raw)
    raise CaptureFormatError("not a pcap, pcapng or btsnoop file (unrecognised magic bytes)")


def _need(raw: bytes, offset: int, n: int, what: str) -> None:
    if offset + n > len(raw):
        raise CaptureFormatError(f"truncated capture while reading {what} at byte {offset}")


def _read_pcap(raw: bytes) -> list[Record]:
    endian, tick = _PCAP_MAGICS[raw[:4]]
    _need(raw, 0, 24, "the pcap header")
    linktype = struct.unpack_from(endian + "I", raw, 20)[0] & 0xFFFF
    out: list[Record] = []
    off = 24
    while off < len(raw):
        _need(raw, off, 16, "a packet header")
        sec, frac, incl, _orig = struct.unpack_from(endian + "IIII", raw, off)
        off += 16
        _need(raw, off, incl, "packet data")
        out.append(Record(linktype, sec + frac * tick, raw[off : off + incl]))
        off += incl
    return out


def _read_pcapng(raw: bytes) -> list[Record]:
    out: list[Record] = []
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per timestamp tick)
    endian = "<"
    off = 0
    while off < len(raw):
        _need(raw, off, 12, "a pcapng block header")
        if raw[off : off + 4] == b"\x0a\x0d\x0d\x0a":  # section header: defines byte order
            magic = raw[off + 8 : off + 12]
            if magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("pcapng section header has a bad byte-order magic")
            interfaces = []
        btype, blen = struct.unpack_from(endian + "II", raw, off)
        if blen < 12 or blen % 4:
            raise CaptureFormatError(f"pcapng block at byte {off} has an invalid length {blen}")
        _need(raw, off, blen, "a pcapng block")
        body = raw[off + 8 : off + blen - 4]
        if btype == 1:  # interface description
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces.append((linktype, _pcapng_tick(body[8:], endian)))
        elif btype == 6:  # enhanced packet
            iface, ts_hi, ts_lo, cap_len, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            if iface >= len(interfaces):
                raise CaptureFormatError(f"packet refers to unknown interface {iface}")
            if 20 + cap_len > len(body):
                raise CaptureFormatError("pcapng packet data runs past its block")
            linktype, tick = interfaces[iface]
            out.append(Record(linktype, ((ts_hi << 32) | ts_lo) * tick, bytes(body[20 : 20 + cap_len])))
        elif btype == 3:  # simple packet (no timestamp)
            if not interfaces:
                raise CaptureFormatError("simple packet block before any interface block")
            (orig,) = struct.unpack_from(endian + "I", body, 0)
            out.append(Record(interfaces[0][0], 0.0, bytes(body[4 : 4 + min(orig, len(body) - 4)])))
        off += blen
    return out


def _pcapng_tick(options: bytes, endian: str) -> float:
    """Seconds per timestamp unit from an interface block's ``if_tsresol`` option (default microseconds)."""
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, off)
        if code == 0:
            break
        value = options[off + 4 : off + 4 + length]
        if code == 9 and value:
            resol = value[0]
            return 2.0 ** -(resol & 0x7F) if resol & 0x80 else 10.0**-resol
        off += 4 + ((length + 3) & ~3)
    return 1e-6


def _read_btsnoop(raw: bytes) -> list[Record]:
    _need(raw, 0, 16, "the btsnoop header")
    version, datalink = struct.unpack_from(">II", raw, 8)
    if version != 1:
        raise CaptureFormatError(f"unsupported btsnoop version {version}")
    if datalink not in (BTSNOOP_DATALINK_HCI_UNENCAPSULATED, BTSNOOP_DATALINK_HCI_H4):
        raise CaptureFormatError(f"unsupported btsnoop datalink type {datalink} (only 1001 and 1002 are handled)")
    out: list[Record] = []
    off = 16
    while off < len(raw):
        _need(raw, off, 24, "a btsnoop record header")
        _orig, incl, flags, _drops, ts = struct.unpack_from(">IIIIq", raw, off)
        off += 24
        _need(raw, off, incl, "btsnoop packet data")
        data = raw[off : off + incl]
        off += incl
        if datalink == BTSNOOP_DATALINK_HCI_UNENCAPSULATED:
            # No H4 type byte: derive it. Command/event flag set -> command (sent) or event (received); else ACL.
            h4 = (1 if not flags & 1 else 4) if flags & 2 else 2
            data = bytes([h4]) + data
        out.append(
            Record(
                LINKTYPE_BLUETOOTH_HCI_H4,
                (ts - _BTSNOOP_EPOCH_OFFSET_US) / 1e6,
                data,
                {"direction": "rx" if flags & 1 else "tx"},
            )
        )
    return out
