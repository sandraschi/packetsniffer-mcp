"""Network packet capture and PCAP analysis tools using Scapy."""

from __future__ import annotations

import os
import time
from typing import Annotated, Literal

import structlog
from pydantic import Field
from scapy.all import ARP, DNS, IP, TCP, UDP, conf, rdpcap, sniff

from packetsniffer_mcp.mcp_instance import mcp

logger = structlog.get_logger(__name__)


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
async def packetsniffer_ops(
    operation: Annotated[
        Literal["list_interfaces", "sniff", "analyze_pcap"],
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
) -> dict:
    """Network interface discovery, live packet capture, and PCAP analysis.

    [RATIONALE] Consolidates local packet sniffing and offline PCAP analysis tools
    to stay under tool limits while providing full companion hacking capability.

    Operations:
    - list_interfaces: List active network interfaces with details.
    - sniff: Sniff live packets on a selected interface (requires administrative privileges).
    - analyze_pcap: Parse a PCAP/PCAPNG capture file and summarize network flows.

    ## Return Format
    {"success": bool, "operation": str, "data": dict | list}

    ## Examples
    await packetsniffer_ops(operation="list_interfaces")
    await packetsniffer_ops(operation="sniff", interface="WiFi", count=10)
    await packetsniffer_ops(operation="analyze_pcap", file_path="C:/path/to/capture.pcap")
    """
    if operation == "list_interfaces":
        return _list_interfaces()
    elif operation == "sniff":
        return _sniff_packets(interface, count, timeout, filter_expr)
    elif operation == "analyze_pcap":
        return _analyze_pcap_file(file_path)
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


def _sniff_packets(
    interface: str | None,
    count: int,
    timeout: int,
    filter_expr: str | None,
) -> dict:
    # Restrict count and timeout values to keep execution safe
    count = min(max(1, count), 500)
    timeout = min(max(1, timeout), 60)

    # Try resolving friendly interface name to GUID on Windows
    iface_id = interface
    if interface and os.name == "nt":
        for name, iface in conf.ifaces.items():
            if getattr(iface, "name", "").lower() == interface.lower():
                iface_id = name
                break

    captured = []

    try:
        # Live sniffing block
        packets = sniff(
            iface=iface_id,
            count=count,
            timeout=timeout,
            filter=filter_expr,
        )

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

        return {
            "success": True,
            "operation": "sniff",
            "data": {
                "count": len(captured),
                "packets": captured,
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
