"""Bluetooth Classic payload extraction from HCI captures (btsnoop, or pcap/pcapng link type 201 / 187).

Pipeline: HCI ACL packets -> L2CAP reassembly per (connection handle, direction) -> channel table from L2CAP
connection request/response (CID -> PSM) -> RFCOMM frames on PSM 3 -> UIH data per DLCI. That is the byte stream
a serial-port-profile (SPP) device such as the DYMO MobileLabeler receives.

Best effort by design. If the capture started after the connection was made, the CID -> PSM mapping is missing;
frames on unknown channels are then tried as RFCOMM and kept only when their FCS checks out.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from .pcapfile import (
    LINKTYPE_BLUETOOTH_HCI_H4,
    LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR,
    CaptureFormatError,
    Record,
    read_records,
)

PSM_RFCOMM = 0x0003
_H4_ACL = 2
_CID_SIGNALLING = 0x0001

# RFCOMM frame control values with the P/F bit masked out
_SABM, _UA, _DM, _DISC, _UIH = 0x2F, 0x63, 0x0F, 0x43, 0xEF


@dataclass(frozen=True)
class BtPayload:
    index: int
    ts: float
    direction: str  # "tx" host to device, "rx" device to host, "unknown"
    handle: int
    cid: int
    psm: int | None
    dlci: int | None
    data: bytes
    fcs_ok: bool | None


def rfcomm_fcs(data: bytes) -> int:
    """RFCOMM frame check sequence: reflected CRC-8 (polynomial 0x07), init 0xFF, result inverted."""
    crc = 0xFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xE0 if crc & 1 else crc >> 1
    return (~crc) & 0xFF


def _hci_packets(records: list[Record]) -> list[tuple[int, float, str, int, bytes]]:
    """Normalise records to ``(index, ts, direction, h4_type, payload)``."""
    out = []
    for i, rec in enumerate(records):
        data = rec.data
        if rec.linktype == LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR:
            if len(data) < 5:
                continue
            direction = "rx" if struct.unpack_from(">I", data, 0)[0] & 1 else "tx"
            data = data[4:]
        elif rec.linktype == LINKTYPE_BLUETOOTH_HCI_H4:
            direction = rec.meta.get("direction", "unknown")
        else:
            raise CaptureFormatError(
                f"link type {rec.linktype} is not Bluetooth HCI (need btsnoop, or pcap link type 187 / 201)"
            )
        if data:
            out.append((i, rec.ts, direction, data[0], data[1:]))
    return out


def _l2cap_pdus(packets: list[tuple[int, float, str, int, bytes]]):
    """Reassemble ACL fragments into ``(index, ts, direction, handle, cid, payload)`` L2CAP PDUs."""
    partial: dict[tuple[int, str], dict[str, Any]] = {}
    for index, ts, direction, h4, payload in packets:
        if h4 != _H4_ACL or len(payload) < 4:
            continue
        handle_flags, length = struct.unpack_from("<HH", payload, 0)
        handle, pb = handle_flags & 0x0FFF, (handle_flags >> 12) & 0x3
        fragment = payload[4 : 4 + length]
        key = (handle, direction)
        if pb == 0b01:  # continuation
            cur = partial.get(key)
            if cur is None:
                continue
            cur["buf"] += fragment
        else:  # start of an L2CAP PDU
            if len(fragment) < 4:
                continue
            l2_len, cid = struct.unpack_from("<HH", fragment, 0)
            cur = partial[key] = {"index": index, "ts": ts, "cid": cid, "need": l2_len, "buf": fragment[4:]}
        if len(cur["buf"]) >= cur["need"]:
            yield cur["index"], cur["ts"], direction, handle, cur["cid"], bytes(cur["buf"][: cur["need"]])
            del partial[key]


def _track_channels(pdus: list[tuple]) -> dict[tuple[int, int], int]:
    """Map ``(handle, cid)`` to PSM from L2CAP connection request/response signalling."""
    pending: dict[tuple[int, int], tuple[int, int]] = {}  # (handle, ident) -> (psm, requester cid)
    cid_psm: dict[tuple[int, int], int] = {}
    for _index, _ts, _direction, handle, cid, payload in pdus:
        if cid != _CID_SIGNALLING:
            continue
        off = 0
        while off + 4 <= len(payload):
            code, ident, length = payload[off], payload[off + 1], struct.unpack_from("<H", payload, off + 2)[0]
            body = payload[off + 4 : off + 4 + length]
            if code == 0x02 and len(body) >= 4:  # connection request: psm, source cid
                psm, scid = struct.unpack_from("<HH", body, 0)
                pending[(handle, ident)] = (psm, scid)
            elif code == 0x03 and len(body) >= 8:  # connection response: dest cid, source cid, result, status
                dcid, scid, result, _status = struct.unpack_from("<HHHH", body, 0)
                req = pending.get((handle, ident))
                if req is not None and result == 0:
                    cid_psm[(handle, req[1])] = req[0]
                    cid_psm[(handle, dcid)] = req[0]
            off += 4 + length
    return cid_psm


def _parse_rfcomm(frame: bytes) -> tuple[int, int, bytes, bool] | None:
    """Return ``(dlci, control, data, fcs_ok)`` for a plausible RFCOMM frame, else None."""
    if len(frame) < 4:
        return None
    addr, control = frame[0], frame[1]
    if not addr & 0x01:  # the EA bit must be set in the address octet
        return None
    dlci = addr >> 2
    if frame[2] & 0x01:
        length, hdr = frame[2] >> 1, 3
    else:
        if len(frame) < 5:
            return None
        length, hdr = (frame[2] >> 1) | (frame[3] << 7), 4
    base = control & ~0x10
    credit = 1 if base == _UIH and control & 0x10 and dlci != 0 else 0
    # With credit-based flow control one extra octet follows the length. Whether the length indicator counts
    # it varies by stack, so take whichever reading makes the frame exactly as long as the L2CAP payload.
    for body_len, skip in ((length, credit), (length - credit, credit)):
        if body_len >= 0 and hdr + credit + body_len + 1 == len(frame):
            body = frame[hdr + skip : hdr + credit + body_len]
            fcs_span = frame[:2] if base == _UIH else frame[:hdr]
            return dlci, control, body, rfcomm_fcs(fcs_span) == frame[-1]
    return None


def extract_payloads(records: list[Record]) -> list[BtPayload]:
    """RFCOMM user data in capture order. Raw L2CAP payloads of other channels are not returned."""
    pdus = list(_l2cap_pdus(_hci_packets(records)))
    channels = _track_channels(pdus)
    out: list[BtPayload] = []
    for index, ts, direction, handle, cid, payload in pdus:
        if cid == _CID_SIGNALLING:
            continue
        psm = channels.get((handle, cid))
        if psm not in (PSM_RFCOMM, None):
            continue
        parsed = _parse_rfcomm(payload)
        if parsed is None:
            continue
        dlci, control, body, fcs_ok = parsed
        if psm is None and not fcs_ok:
            continue  # unknown channel: only trust frames whose checksum verifies
        if (control & ~0x10) != _UIH or dlci == 0 or not body:
            continue  # connection management, control channel (DLCI 0) or empty keep-alive
        out.append(BtPayload(index, ts, direction, handle, cid, psm, dlci, body, fcs_ok))
    return out


def load_bt_capture(path: str) -> list[BtPayload]:
    """Read a btsnoop / pcap / pcapng Bluetooth capture and return RFCOMM payloads."""
    _fmt, records = read_records(path)
    if not records:
        raise CaptureFormatError("the capture contains no packets")
    return extract_payloads(records)
