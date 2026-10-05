"""MCP operation implementations for hardware-protocol capture analysis (kept out of the tool module)."""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import usbpcapcmd
from .btsnoop import BtPayload, extract_payloads
from .diff import diff_streams, diff_transfers
from .pcapfile import (
    LINKTYPE_BLUETOOTH_HCI_H4,
    LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR,
    LINKTYPE_USBPCAP,
    CaptureFormatError,
    read_records,
)
from .usbpcap import (
    UsbTransfer,
    describe_devices,
    filter_transfers,
    parse_usbpcap,
    transfer_type_names,
)

MAX_HEX_BYTES = 4096


def _fail(operation: str, error: str, error_type: str, suggestions: list[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"success": False, "operation": operation, "error_type": error_type, "error": error}
    if suggestions:
        out["suggestions"] = suggestions
    return out


def _hex(data: bytes, max_bytes: int) -> tuple[str, bool]:
    return data[:max_bytes].hex(" "), len(data) > max_bytes


def _check_direction(direction: str) -> str:
    if direction not in ("out", "in", "both"):
        raise ValueError("direction must be 'out' (host to device), 'in' (device to host) or 'both'")
    return direction


def _export(path: str | None, stream: bytes) -> str | None:
    if not path:
        return None
    target = Path(path).expanduser()
    if target.suffix.lower() not in (".bin", ".dat", ".raw"):
        raise ValueError("export_path must end in .bin, .dat or .raw")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(stream)
    return str(target)


def _stream_info(stream: bytes) -> dict[str, Any]:
    return {"length": len(stream), "sha256_16": hashlib.sha256(stream).hexdigest()[:16]}


def _usb_view(
    file_path: str,
    direction: str,
    device: int | None,
    endpoint: int | None,
    transfer_types: str | None,
) -> tuple[list[UsbTransfer], list[UsbTransfer]]:
    """Returns ``(all_transfers, selected_transfers)``."""
    _fmt, records = read_records(file_path)
    if not records:
        raise CaptureFormatError("the capture contains no packets")
    everything = parse_usbpcap(records)
    chosen = filter_transfers(
        everything,
        direction=_check_direction(direction),
        device=device,
        endpoint=endpoint,
        transfer_types=transfer_type_names(transfer_types),
    )
    return everything, chosen


def usb_payloads(
    file_path: str | None,
    *,
    direction: str = "out",
    device: int | None = None,
    endpoint: int | None = None,
    transfer_types: str | None = None,
    limit: int = 100,
    max_bytes: int = 256,
    export_path: str | None = None,
) -> dict[str, Any]:
    """Data carried by each USB transfer in a USBPcap capture, plus device/interface descriptors if captured."""
    op = "usb_payloads"
    if not file_path:
        return _fail(op, "No file_path provided", "invalid_request")
    try:
        everything, chosen = _usb_view(file_path, direction, device, endpoint, transfer_types)
        limit, max_bytes = min(max(1, limit), 500), min(max(1, max_bytes), MAX_HEX_BYTES)
        stream = b"".join(t.data for t in chosen)
        first_ts = everything[0].ts if everything else 0.0

        groups: dict[tuple[int, int, str, str], list[int]] = defaultdict(lambda: [0, 0])
        for t in chosen:
            g = groups[(t.device, t.endpoint & 0x7F, t.direction, t.transfer)]
            g[0] += 1
            g[1] += len(t.data)

        items = []
        for t in chosen[:limit]:
            text, cut = _hex(t.data, max_bytes)
            items.append(
                {
                    "n": len(items),
                    "record": t.index,
                    "t": round(t.ts - first_ts, 6),
                    "device": t.device,
                    "endpoint": f"0x{t.endpoint:02x}",
                    "direction": t.direction,
                    "transfer": t.transfer,
                    "length": len(t.data),
                    "hex": text,
                    "truncated": cut,
                }
            )
        return {
            "success": True,
            "operation": op,
            "data": {
                "file_name": os.path.basename(file_path),
                "transfers_in_capture": len(everything),
                "selected": len(chosen),
                "returned": len(items),
                "stream": _stream_info(stream),
                "exported_to": _export(export_path, stream),
                "endpoints": [
                    {"device": d, "endpoint": f"0x{e:02x}", "direction": dr, "transfer": tr, "transfers": n, "bytes": b}
                    for (d, e, dr, tr), (n, b) in sorted(groups.items())
                ],
                "devices": describe_devices(everything),
                "transfers": items,
            },
        }
    except CaptureFormatError as exc:
        return _fail(op, str(exc), "invalid_capture")
    except ValueError as exc:
        return _fail(op, str(exc), "invalid_request")


def btsnoop_payloads(
    file_path: str | None,
    *,
    direction: str = "tx",
    limit: int = 100,
    max_bytes: int = 256,
    export_path: str | None = None,
) -> dict[str, Any]:
    """RFCOMM (serial port profile) user data from a Bluetooth HCI capture."""
    op = "btsnoop_payloads"
    if not file_path:
        return _fail(op, "No file_path provided", "invalid_request")
    if direction not in ("tx", "rx", "both"):
        return _fail(op, "direction must be 'tx' (host to device), 'rx' (device to host) or 'both'", "invalid_request")
    try:
        _fmt, records = read_records(file_path)
        if not records:
            raise CaptureFormatError("the capture contains no packets")
        payloads = extract_payloads(records)
        chosen = [p for p in payloads if direction == "both" or p.direction == direction]
        limit, max_bytes = min(max(1, limit), 500), min(max(1, max_bytes), MAX_HEX_BYTES)
        stream = b"".join(p.data for p in chosen)
        first_ts = records[0].ts

        items = []
        for p in chosen[:limit]:
            text, cut = _hex(p.data, max_bytes)
            items.append(
                {
                    "n": len(items),
                    "record": p.index,
                    "t": round(p.ts - first_ts, 6),
                    "direction": p.direction,
                    "handle": p.handle,
                    "cid": p.cid,
                    "psm": p.psm,
                    "dlci": p.dlci,
                    "length": len(p.data),
                    "fcs_ok": p.fcs_ok,
                    "hex": text,
                    "truncated": cut,
                }
            )
        notes = []
        if not payloads:
            notes.append(
                "No RFCOMM data found. Either the capture has no serial-port traffic, or it began after the "
                "connection was made and the frames could not be verified. Capture from before pairing/connecting."
            )
        if direction == "tx" and any(p.direction == "unknown" for p in payloads):
            notes.append("This capture format has no direction flag; use direction='both'.")
        return {
            "success": True,
            "operation": op,
            "data": {
                "file_name": os.path.basename(file_path),
                "rfcomm_payloads_in_capture": len(payloads),
                "selected": len(chosen),
                "returned": len(items),
                "stream": _stream_info(stream),
                "exported_to": _export(export_path, stream),
                "notes": notes,
                "payloads": items,
            },
        }
    except CaptureFormatError as exc:
        return _fail(op, str(exc), "invalid_capture")
    except ValueError as exc:
        return _fail(op, str(exc), "invalid_request")


def _kind_of(file_path: str) -> str:
    _fmt, records = read_records(file_path)
    if not records:
        raise CaptureFormatError(f"{os.path.basename(file_path)} contains no packets")
    link = records[0].linktype
    if link == LINKTYPE_USBPCAP:
        return "usb"
    if link in (LINKTYPE_BLUETOOTH_HCI_H4, LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR):
        return "bluetooth"
    raise CaptureFormatError(f"{os.path.basename(file_path)}: link type {link} is neither USBPcap nor Bluetooth HCI")


def _payload_chunks(
    file_path: str, kind: str, direction: str, device: int | None, endpoint: int | None
) -> tuple[list[bytes], str]:
    if kind == "usb":
        _all, chosen = _usb_view(file_path, "out" if direction in ("", "tx") else direction, device, endpoint, None)
        return [t.data for t in chosen], "usb"
    _fmt, records = read_records(file_path)
    payloads: list[BtPayload] = extract_payloads(records)
    want = {"out": "tx", "in": "rx"}.get(direction, direction)
    return [p.data for p in payloads if want == "both" or p.direction == want], "bluetooth"


def diff_captures(
    file_path: str | None,
    file_path_b: str | None,
    *,
    capture_kind: str = "auto",
    direction: str = "out",
    device: int | None = None,
    endpoint: int | None = None,
) -> dict[str, Any]:
    """Compare the host-to-device byte streams of two captures (e.g. blank label vs one-dot label)."""
    op = "diff_captures"
    if not file_path or not file_path_b:
        return _fail(op, "file_path and file_path_b are both required", "invalid_request")
    if capture_kind not in ("auto", "usb", "bluetooth"):
        return _fail(op, "capture_kind must be 'auto', 'usb' or 'bluetooth'", "invalid_request")
    try:
        kind_a = _kind_of(file_path) if capture_kind == "auto" else capture_kind
        kind_b = _kind_of(file_path_b) if capture_kind == "auto" else capture_kind
        if kind_a != kind_b:
            return _fail(op, f"the captures are different kinds ({kind_a} vs {kind_b})", "invalid_request")
        chunks_a, kind = _payload_chunks(file_path, kind_a, direction, device, endpoint)
        chunks_b, _ = _payload_chunks(file_path_b, kind_b, direction, device, endpoint)
        return {
            "success": True,
            "operation": op,
            "data": {
                "kind": kind,
                "direction": direction,
                "file_a": os.path.basename(file_path),
                "file_b": os.path.basename(file_path_b),
                "stream": diff_streams(b"".join(chunks_a), b"".join(chunks_b)),
                "transfers": diff_transfers(chunks_a, chunks_b),
            },
        }
    except CaptureFormatError as exc:
        return _fail(op, str(exc), "invalid_capture")
    except ValueError as exc:
        return _fail(op, str(exc), "invalid_request")


def usb_list_hubs() -> dict[str, Any]:
    op = "usb_list_hubs"
    try:
        return {"success": True, "operation": op, "data": {"hubs": usbpcapcmd.list_hubs()}}
    except usbpcapcmd.UsbPcapError as exc:
        return _fail(op, str(exc), exc.error_type, exc.suggestions)


def usb_capture(
    save_path: str | None, *, hub: str | None, seconds: int, devices: str | None, inject_descriptors: bool
) -> dict[str, Any]:
    op = "usb_capture"
    if not save_path:
        return _fail(op, "save_path is required (where to write the USBPcap capture)", "invalid_request")
    if not hub:
        return _fail(op, "hub is required, e.g. \\\\.\\USBPcap1 (see usb_list_hubs)", "invalid_request")
    target = Path(save_path).expanduser()
    if target.suffix.lower() not in (".pcap", ".pcapng"):
        target = target.with_suffix(".pcap")
    try:
        result = usbpcapcmd.capture(
            str(target), hub=hub, seconds=seconds, devices=devices, inject_descriptors=inject_descriptors
        )
        return {"success": True, "operation": op, "data": result}
    except usbpcapcmd.UsbPcapError as exc:
        return _fail(op, str(exc), exc.error_type, exc.suggestions)
