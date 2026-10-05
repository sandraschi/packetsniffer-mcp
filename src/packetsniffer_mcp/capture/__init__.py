"""Hardware-protocol capture analysis: USBPcap and Bluetooth HCI payload extraction, capture diffing.

Pure Python (no tshark, no scapy dissectors) so it works on a bare machine and is testable with synthetic
captures. Aimed at reverse engineering device protocols: get the bytes the host sent to a device out of a capture.
"""

from .pcapfile import CaptureFormatError, Record, read_records

__all__ = ["CaptureFormatError", "Record", "read_records"]
