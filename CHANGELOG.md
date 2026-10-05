# Changelog: packetsniffer-mcp

## [Unreleased]

### Added
- Hardware-protocol capture analysis for reverse engineering devices, as new `packetsniffer_ops` operations:
  `usb_payloads` (USBPcap transfers, per-endpoint totals, device/interface descriptors, stream export),
  `btsnoop_payloads` (Bluetooth Classic RFCOMM data from btsnoop or pcap/pcapng HCI captures),
  `diff_captures` (compare two captures' host-to-device streams), and `usb_list_hubs` / `usb_capture`
  (wrap USBPcapCMD; unverified live). New `packetsniffer_mcp.capture` package, pure Python, no tshark needed.
  With tshark installed, `tests/test_capture_tshark.py` cross-checks the decoders against Wireshark's dissectors.

### Fixed
- `packetsniffer_ops` advertised only `list_interfaces`, `sniff` and `analyze_pcap` in its schema, so MCP clients
  could not call `start_capture`, `capture_status`, `stop_capture` or `decode_pcap`. All operations are now listed;
  a regression test checks the schema against the dispatch.

## [0.1.0] - 2026-06-24 - Initial Scaffold
- FastMCP 3.4+ dual transport (stdio + HTTP)
- Sampling handler (Ollama/LM Studio compatible)
- Agentic workflow, Prefab UI card, prompts, skills
- Fleet files: justfile, llms.txt, glama.json
- PyInstaller entry point (run_server.py)
- CI (Windows), tests, docs
