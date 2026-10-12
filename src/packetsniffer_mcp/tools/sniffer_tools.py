"""Network packet capture and PCAP analysis tools using Scapy."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Annotated, Literal

import structlog
from pydantic import Field
from scapy.all import ARP, DNS, IP, TCP, UDP, conf, rdpcap, sniff, wrpcap

from packetsniffer_mcp.capture import ops as capture_ops
from packetsniffer_mcp.mcp_instance import mcp

logger = structlog.get_logger(__name__)

# Safety ceiling for a blocking sniff call; raise via env for long captures.
MAX_SNIFF_SECONDS = int(os.getenv("PACKETSNIFFER_MCP_MAX_SNIFF_SECONDS", "300"))
MAX_SNIFF_COUNT = int(os.getenv("PACKETSNIFFER_MCP_MAX_SNIFF_COUNT", "1000"))

# Background captures (start_capture / capture_status / stop_capture).
_capture_lock = threading.Lock()
_active_captures: dict[str, dict] = {}


# Not read-only: captures and exports write files (save_path, export_path) and usb_capture starts a capture driver.
@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
async def packetsniffer_ops(
    operation: Annotated[
        Literal[
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
        ],
        Field(description="Operation to perform."),
    ],
    interface: Annotated[
        str | None,
        Field(description="Network interface identifier (name or GUID) for sniffing."),
    ] = None,
    count: Annotated[
        int,
        Field(description="Number of packets to capture (default: 50, max: 500)."),
    ] = 50,
    timeout: Annotated[
        int,
        Field(description="Timeout in seconds for capture (default: 10, max: 60)."),
    ] = 10,
    filter_expr: Annotated[
        str | None,
        Field(description="BPF filter expression (e.g. 'tcp port 80', 'udp', 'host 192.168.1.100')."),
    ] = None,
    file_path: Annotated[
        str | None,
        Field(description="Absolute path to the PCAP file for 'analyze_pcap' operation."),
    ] = None,
    save_path: Annotated[
        str | None,
        Field(
            description="Absolute path to write captured packets as a PCAP file (e.g. 'C:/captures/out.pcap'). Used by 'sniff' and 'stop_capture'."
        ),
    ] = None,
    capture_id: Annotated[
        str | None,
        Field(description="Capture ID from 'start_capture'. Required for 'capture_status' and 'stop_capture'."),
    ] = None,
    limit: Annotated[
        int,
        Field(
            description="Max packets/transfers returned by 'decode_pcap', 'usb_payloads' and 'btsnoop_payloads' (default: 100, max: 500)."
        ),
    ] = 100,
    file_path_b: Annotated[
        str | None,
        Field(description="Second capture file for 'diff_captures' (file_path is the first)."),
    ] = None,
    direction: Annotated[
        str,
        Field(
            description=(
                "Which way the bytes travelled. USB: 'out' (host to device, default), 'in', 'both'. "
                "Bluetooth: 'tx' (host to device, default), 'rx', 'both'. 'diff_captures' accepts either spelling."
            )
        ),
    ] = "out",
    usb_hub: Annotated[
        str | None,
        Field(description="USBPcap filter device for 'usb_capture', e.g. '\\\\.\\USBPcap1' (see 'usb_list_hubs')."),
    ] = None,
    usb_devices: Annotated[
        str | None,
        Field(
            description="'usb_capture' only: comma list of device addresses to capture (default: all devices on the hub)."
        ),
    ] = None,
    usb_device: Annotated[
        int | None,
        Field(description="USB device address to select in 'usb_payloads' / 'diff_captures' (default: all devices)."),
    ] = None,
    usb_endpoint: Annotated[
        int | None,
        Field(
            description="USB endpoint number to select in 'usb_payloads' / 'diff_captures' (e.g. 2 for endpoint 0x02)."
        ),
    ] = None,
    transfer_types: Annotated[
        str | None,
        Field(
            description="Comma list of USB transfer types for 'usb_payloads': bulk, interrupt, control, isochronous (default: bulk,interrupt)."
        ),
    ] = None,
    max_bytes: Annotated[
        int,
        Field(
            description="Bytes of hex shown per transfer in 'usb_payloads' / 'btsnoop_payloads' (default: 256, max: 4096)."
        ),
    ] = 256,
    export_path: Annotated[
        str | None,
        Field(
            description="Write the selected byte stream to this file (.bin/.dat/.raw) for 'usb_payloads' / 'btsnoop_payloads'."
        ),
    ] = None,
    inject_descriptors: Annotated[
        bool,
        Field(
            description="'usb_capture': ask USBPcap to inject descriptors of already-connected devices (default: false)."
        ),
    ] = False,
) -> dict:
    """Network interface discovery, live packet capture, and PCAP analysis.

    [RATIONALE] Consolidates local packet sniffing, background captures, and offline
    PCAP analysis tools to stay under tool limits while providing full companion
    hacking capability.

    Operations:
    - list_interfaces: List active network interfaces with details.
    - sniff: Blocking capture for the given count/timeout (requires admin privileges).
      Pass save_path to persist the capture to a PCAP file for later analysis or evidence.
    - start_capture: Start a capture in the background (non-blocking). Returns a
      capture_id immediately; the capture runs in a server thread until count/timeout
      is reached or stop_capture is called. In HTTP daemon mode the capture survives
      across agent sessions. Poll with capture_status.
    - capture_status: Status of one capture (capture_id) or all active captures.
    - stop_capture: Request a stop (takes effect on the next packet, or at timeout).
      Returns packets captured so far; pass save_path to persist them.
    - decode_pcap: Deep protocol decode of a PCAP/PCAPNG file via tshark (optional
      dependency - install Wireshark). Extracts decoded fields Scapy's thin
      dissectors miss: DNS query/answer names, HTTP requests, TLS SNI hostnames
      (catches encrypted phone-home domains). Use limit to bound output.
    - analyze_pcap: Parse a PCAP/PCAPNG capture file and summarize network flows.

    Hardware-protocol reverse engineering (pure Python, no tshark needed; for working out what bytes a host
    sends a device such as a label printer):
    - usb_list_hubs: List USB root hubs USBPcap can capture on (needs USBPcap installed; UNVERIFIED live).
    - usb_capture: Capture USB traffic with USBPcapCMD for 'timeout' seconds into save_path (needs USBPcap
      and administrator rights; UNVERIFIED live). Print/operate the device during the window.
    - usb_payloads: From a USBPcap capture, the data of each transfer (default host-to-device bulk/interrupt),
      per-endpoint totals, and any device/interface descriptors in the capture (answers "printer class, HID,
      or vendor-specific?"). export_path writes the concatenated stream to a .bin file.
    - btsnoop_payloads: From a Bluetooth HCI capture (btsnoop, or pcap/pcapng link type 187/201), the RFCOMM
      serial-port-profile data. Best effort: capture from before the connection is made.
    - diff_captures: Compare two captures' host-to-device streams (file_path vs file_path_b): shared prefix and
      suffix, changed byte ranges, per-transfer differences. For controlled experiments (blank label vs one dot).

    ## Return Format
    {"success": bool, "operation": str, "data": dict | list}

    ## Examples
    await packetsniffer_ops(operation="list_interfaces")
    await packetsniffer_ops(operation="sniff", interface="WiFi", count=10)
    await packetsniffer_ops(operation="sniff", filter_expr="udp port 53", count=200, timeout=120, save_path="C:/captures/dns.pcap")
    await packetsniffer_ops(operation="start_capture", filter_expr="udp port 53", count=1000, timeout=300)
    await packetsniffer_ops(operation="capture_status", capture_id="a1b2c3d4")
    await packetsniffer_ops(operation="stop_capture", capture_id="a1b2c3d4", save_path="C:/captures/dns.pcap")
    await packetsniffer_ops(operation="decode_pcap", file_path="C:/captures/dns.pcap", limit=100)
    await packetsniffer_ops(operation="analyze_pcap", file_path="C:/captures/dns.pcap")
    await packetsniffer_ops(operation="usb_list_hubs")
    await packetsniffer_ops(operation="usb_capture", usb_hub="\\\\.\\USBPcap1", timeout=30, save_path="C:/captures/02-dot.pcap")
    await packetsniffer_ops(operation="usb_payloads", file_path="C:/captures/02-dot.pcap", export_path="C:/captures/02-dot.bin")
    await packetsniffer_ops(operation="btsnoop_payloads", file_path="C:/captures/btsnoop_hci.log", direction="tx")
    await packetsniffer_ops(operation="diff_captures", file_path="C:/captures/01-blank.pcap", file_path_b="C:/captures/02-dot.pcap")
    """
    if operation == "list_interfaces":
        return _list_interfaces()
    elif operation == "sniff":
        return _sniff_packets(interface, count, timeout, filter_expr, save_path)
    elif operation == "start_capture":
        return _start_capture(interface, count, timeout, filter_expr, save_path)
    elif operation == "capture_status":
        return _capture_status(capture_id)
    elif operation == "stop_capture":
        return _stop_capture(capture_id, save_path)
    elif operation == "decode_pcap":
        return await asyncio.to_thread(_decode_pcap, file_path, limit)
    elif operation == "analyze_pcap":
        return _analyze_pcap_file(file_path)
    elif operation == "usb_list_hubs":
        return capture_ops.usb_list_hubs()
    elif operation == "usb_capture":
        seconds = min(max(1, timeout), MAX_SNIFF_SECONDS)
        return await asyncio.to_thread(
            capture_ops.usb_capture,
            save_path,
            hub=usb_hub,
            seconds=seconds,
            devices=usb_devices,
            inject_descriptors=inject_descriptors,
        )
    elif operation == "usb_payloads":
        return capture_ops.usb_payloads(
            file_path,
            direction=direction,
            device=usb_device,
            endpoint=usb_endpoint,
            transfer_types=transfer_types,
            limit=limit,
            max_bytes=max_bytes,
            export_path=export_path,
        )
    elif operation == "btsnoop_payloads":
        # The shared 'direction' default is the USB spelling; map it for Bluetooth callers who leave it alone.
        bt_direction = {"out": "tx", "in": "rx"}.get(direction, direction)
        return capture_ops.btsnoop_payloads(
            file_path, direction=bt_direction, limit=limit, max_bytes=max_bytes, export_path=export_path
        )
    elif operation == "diff_captures":
        return capture_ops.diff_captures(
            file_path, file_path_b, direction=direction, device=usb_device, endpoint=usb_endpoint
        )
    return {"success": False, "error": f"Unknown operation: {operation}"}


def _list_interfaces() -> dict:
    interfaces = []
    for name, iface in conf.ifaces.items():
        # Scapy interfaces have different structures depending on the OS/version
        desc = getattr(iface, "description", "") or getattr(iface, "name", "")
        ip_addr = getattr(iface, "ip", "") or ""
        mac_addr = getattr(iface, "mac", "") or ""

        # Filter out obvious loopbacks and empty interface rows unless they have IP address
        if not ip_addr and "loopback" in desc.lower():
            continue

        interfaces.append(
            {
                "id": name,
                "name": getattr(iface, "name", name),
                "description": desc,
                "ip": ip_addr,
                "mac": mac_addr,
                "is_loopback": "loopback" in desc.lower() or ip_addr == "127.0.0.1",
            }
        )

    return {
        "success": True,
        "operation": "list_interfaces",
        "data": interfaces,
    }


def _resolve_interface(interface: str | None) -> str | None:
    """Resolve a friendly interface name to Scapy's internal ID on Windows."""
    iface_id = interface
    if interface and os.name == "nt":
        for name, iface in conf.ifaces.items():
            if getattr(iface, "name", "").lower() == interface.lower():
                iface_id = name
                break
    return iface_id


def _summarize_packets(packets) -> list[dict]:
    """Convert Scapy packets into compact JSON summaries for agent consumption."""
    captured = []
    for i, pkt in enumerate(packets):
        summary = pkt.summary()
        length = len(pkt)
        time_epoch = float(pkt.time)

        proto = "OTHER"
        src = "unknown"
        dst = "unknown"
        info = {}

        if pkt.haslayer(IP):
            proto = "IP"
            src = pkt[IP].src
            dst = pkt[IP].dst

            if pkt.haslayer(TCP):
                proto = "TCP"
                info["sport"] = pkt[TCP].sport
                info["dport"] = pkt[TCP].dport
                info["flags"] = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                info["sport"] = pkt[UDP].sport
                info["dport"] = pkt[UDP].dport
                if pkt.haslayer(DNS):
                    proto = "DNS"
                    info["dns_summary"] = pkt[DNS].summary()
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            info["op"] = pkt[ARP].op

        captured.append(
            {
                "index": i,
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_epoch)),
                "length": length,
                "protocol": proto,
                "src": src,
                "dst": dst,
                "summary": summary,
                "info": info,
            }
        )
    return captured


def _sniff_packets(
    interface: str | None,
    count: int,
    timeout: int,
    filter_expr: str | None,
    save_path: str | None,
) -> dict:
    # Bound capture to keep execution safe. Ceilings are configurable via env:
    # PACKETSNIFFER_MCP_MAX_SNIFF_SECONDS / PACKETSNIFFER_MCP_MAX_SNIFF_COUNT.
    count = min(max(1, count), MAX_SNIFF_COUNT)
    timeout = min(max(1, timeout), MAX_SNIFF_SECONDS)

    iface_id = _resolve_interface(interface)

    try:
        # Live sniffing block
        packets = sniff(
            iface=iface_id,
            count=count,
            timeout=timeout,
            filter=filter_expr,
        )

        captured = _summarize_packets(packets)

        return {
            "success": True,
            "operation": "sniff",
            "data": {
                "count": len(captured),
                "packets": captured,
                "saved_to": _save_capture(packets, save_path) if save_path else None,
            },
        }
    except Exception as e:
        logger.error("Live sniffing failed", error=str(e))
        return {
            "success": False,
            "operation": "sniff",
            "error": (
                "Capture failed. Ensure you are running with administrator privileges "
                f"if doing live capture. Details: {e}"
            ),
        }


def _save_capture(packets, save_path: str) -> str:
    """Persist captured packets to a PCAP file; returns the absolute path."""
    path = Path(save_path).expanduser()
    if path.suffix.lower() not in (".pcap", ".pcapng"):
        path = path.with_suffix(".pcap")
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return str(path)


def _start_capture(
    interface: str | None,
    count: int,
    timeout: int,
    filter_expr: str | None,
    save_path: str | None,
) -> dict:
    """Launch a background capture; returns immediately with a capture_id."""
    count = min(max(1, count), MAX_SNIFF_COUNT)
    timeout = min(max(1, timeout), MAX_SNIFF_SECONDS)
    capture_id = uuid.uuid4().hex[:8]
    stop_event = threading.Event()

    capture = {
        "id": capture_id,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "interface": interface,
        "filter_expr": filter_expr,
        "count": count,
        "timeout": timeout,
        "save_path": save_path,
        "stop_event": stop_event,
        "packets": None,
        "saved_to": None,
        "error": None,
    }
    with _capture_lock:
        _active_captures[capture_id] = capture

    thread = threading.Thread(
        target=_capture_worker,
        args=(capture_id,),
        daemon=True,
        name=f"sniff-{capture_id}",
    )
    capture["thread"] = thread
    thread.start()

    return {
        "success": True,
        "operation": "start_capture",
        "data": {
            "capture_id": capture_id,
            "status": "running",
            "stop_after": f"{timeout}s or {count} packets",
        },
    }


def _capture_worker(capture_id: str) -> None:
    """Background sniff loop; ends on count/timeout or when stop is requested."""
    with _capture_lock:
        cap = _active_captures.get(capture_id)
    if cap is None:
        return
    try:
        packets = sniff(
            iface=_resolve_interface(cap["interface"]),
            count=cap["count"],
            timeout=cap["timeout"],
            filter=cap["filter_expr"],
            stop_filter=lambda pkt: cap["stop_event"].is_set(),
        )
        saved_to = _save_capture(packets, cap["save_path"]) if cap["save_path"] else None
        with _capture_lock:
            cap["packets"] = packets
            cap["saved_to"] = saved_to
            cap["status"] = "done"
    except Exception as e:
        logger.error("Background capture failed", capture_id=capture_id, error=str(e))
        with _capture_lock:
            cap["error"] = str(e)
            cap["status"] = "error"


def _capture_status(capture_id: str | None) -> dict:
    """Status of one capture (by capture_id) or all active captures."""
    with _capture_lock:
        if capture_id is None:
            captures = list(_active_captures.values())
        else:
            captures = [c for c in _active_captures.values() if c["id"] == capture_id]
    if capture_id and not captures:
        return {
            "success": False,
            "operation": "capture_status",
            "error": f"No capture with id {capture_id}",
        }

    entries = []
    for c in captures:
        entry = {
            "capture_id": c["id"],
            "status": c["status"],
            "started_at": c["started_at"],
            "interface": c["interface"],
            "filter_expr": c["filter_expr"],
            "count": c["count"],
            "timeout": c["timeout"],
            "saved_to": c["saved_to"],
            "error": c["error"],
        }
        if c["packets"] is not None:
            entry["packet_count"] = len(c["packets"])
        entries.append(entry)

    return {
        "success": True,
        "operation": "capture_status",
        "data": entries[0] if capture_id else entries,
    }


def _stop_capture(capture_id: str | None, save_path: str | None) -> dict:
    """Stop a capture and return packets collected so far."""
    if not capture_id:
        return {"success": False, "operation": "stop_capture", "error": "capture_id is required"}
    with _capture_lock:
        cap = _active_captures.get(capture_id)
    if cap is None:
        return {"success": False, "operation": "stop_capture", "error": f"No capture with id {capture_id}"}

    cap["stop_event"].set()
    thread = cap.get("thread")
    if thread and thread.is_alive():
        # stop_filter only runs on the next packet; wait briefly, don't block forever
        thread.join(timeout=15)

    with _capture_lock:
        status = cap["status"]
        packets = cap["packets"]
        error = cap["error"]
        saved_to = cap["saved_to"]

    if status == "error":
        return {
            "success": False,
            "operation": "stop_capture",
            "error": f"Capture failed: {error}",
        }
    if packets is None:
        return {
            "success": True,
            "operation": "stop_capture",
            "data": {
                "capture_id": capture_id,
                "status": "stopping",
                "message": "Stop requested; capture is still finishing (waits for the next packet or the timeout). Poll capture_status.",
            },
        }

    if save_path and not saved_to:
        saved_to = _save_capture(packets, save_path)

    return {
        "success": True,
        "operation": "stop_capture",
        "data": {
            "capture_id": capture_id,
            "status": "done",
            "count": len(packets),
            "packets": _summarize_packets(packets),
            "saved_to": saved_to,
        },
    }


def _analyze_pcap_file(file_path: str | None) -> dict:
    if not file_path:
        return {"success": False, "operation": "analyze_pcap", "error": "No file_path provided"}

    if not os.path.exists(file_path):
        return {"success": False, "operation": "analyze_pcap", "error": f"File does not exist: {file_path}"}

    try:
        packets = rdpcap(file_path)

        flows: dict[tuple[str, str, str], int] = {}
        protocols: dict[str, int] = {}
        total_bytes = 0
        packets_summary = []

        for i, pkt in enumerate(packets):
            total_bytes += len(pkt)
            proto = "OTHER"
            src = "MAC:" + pkt.src if hasattr(pkt, "src") else "unknown"
            dst = "MAC:" + pkt.dst if hasattr(pkt, "dst") else "unknown"

            if pkt.haslayer(IP):
                proto = "IPv4"
                src = pkt[IP].src
                dst = pkt[IP].dst

                if pkt.haslayer(TCP):
                    proto = "TCP"
                elif pkt.haslayer(UDP):
                    proto = "UDP"
            elif pkt.haslayer(ARP):
                proto = "ARP"
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst

            protocols[proto] = protocols.get(proto, 0) + 1
            flow_key = (src, dst, proto)
            flows[flow_key] = flows.get(flow_key, 0) + 1

            # Keep first 100 packets detailed summary to prevent context blowup
            if i < 100:
                packets_summary.append(
                    {
                        "index": i,
                        "time": float(pkt.time),
                        "length": len(pkt),
                        "proto": proto,
                        "src": src,
                        "dst": dst,
                        "summary": pkt.summary(),
                    }
                )

        # Format flows for JSON response
        formatted_flows = [
            {"src": f[0], "dst": f[1], "protocol": f[2], "count": count}
            for f, count in sorted(flows.items(), key=lambda x: x[1], reverse=True)
        ]

        return {
            "success": True,
            "operation": "analyze_pcap",
            "data": {
                "file_name": os.path.basename(file_path),
                "total_packets": len(packets),
                "total_bytes": total_bytes,
                "protocols": protocols,
                "flows": formatted_flows[:50],  # Top 50 flows
                "packets_preview": packets_summary,
            },
        }
    except Exception as e:
        logger.error("PCAP analysis failed", error=str(e))
        return {
            "success": False,
            "operation": "analyze_pcap",
            "error": f"Failed to parse PCAP file: {e}",
        }


# Fields worth surfacing from tshark's deep dissection (Scapy's dissectors are thin).
_TSHARK_FIELDS = {
    "frame": ["frame.time", "frame.len"],
    "ip": ["ip.src", "ip.dst", "ip.proto"],
    "tcp": ["tcp.srcport", "tcp.dstport", "tcp.flags.str"],
    "udp": ["udp.srcport", "udp.dstport"],
    "dns": ["dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.resp.name"],
    "http": ["http.request.method", "http.host", "http.request.uri", "http.response.code", "http.user_agent"],
    "tls": ["tls.handshake.extensions_server_name", "tls.handshake.type", "tls.record.version"],
}


def _flatten_layers(layers: dict) -> dict:
    """Extract the interesting decoded fields from one tshark JSON packet."""
    out = {}
    for layer_name, fields in _TSHARK_FIELDS.items():
        layer = layers.get(layer_name)
        if not isinstance(layer, dict):
            continue
        for field in fields:
            value = layer.get(field)
            if isinstance(value, list):
                value = value[0] if value else None
            if isinstance(value, dict) or value is None:
                continue
            out[field] = value
    return out


def _decode_pcap(file_path: str | None, limit: int) -> dict:
    """Deep protocol decode via tshark (optional dependency - install Wireshark)."""
    if not file_path:
        return {"success": False, "operation": "decode_pcap", "error": "No file_path provided"}
    if not os.path.exists(file_path):
        return {"success": False, "operation": "decode_pcap", "error": f"File does not exist: {file_path}"}

    tshark = shutil.which("tshark")
    if not tshark:
        return {
            "success": False,
            "operation": "decode_pcap",
            "error_type": "missing_dependency",
            "error": (
                "tshark not found on PATH. Install Wireshark to enable deep protocol "
                "decode (DNS answers, HTTP requests, TLS SNI hostnames)."
            ),
            "suggestions": [
                "winget install Wireshark",
                "Or keep using analyze_pcap (Scapy) for flow-level summaries.",
            ],
        }

    limit = min(max(1, limit), 500)
    try:
        proc = subprocess.run(
            [tshark, "-r", file_path, "-T", "json", "-c", str(limit)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "operation": "decode_pcap",
            "error": f"tshark exceeded 90s on {file_path}",
        }
    if proc.returncode != 0:
        return {
            "success": False,
            "operation": "decode_pcap",
            "error": f"tshark failed: {(proc.stderr or '').strip()[:500]}",
        }

    try:
        decoded = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "operation": "decode_pcap",
            "error": f"Failed to parse tshark output: {e}",
        }

    packets = []
    for entry in decoded:
        layers = entry.get("_source", {}).get("layers", {})
        packets.append(_flatten_layers(layers))

    return {
        "success": True,
        "operation": "decode_pcap",
        "data": {
            "file_name": os.path.basename(file_path),
            "decoded": len(packets),
            "packets": packets,
        },
    }
