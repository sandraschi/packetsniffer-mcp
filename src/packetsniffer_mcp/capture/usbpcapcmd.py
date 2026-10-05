"""Wrapper around USBPcap's command line tool (``USBPcapCMD.exe``) for live USB capture on Windows.

UNVERIFIED against a real USBPcap install: the command line below follows USBPcap's documented options
(``-d`` filter device, ``-o`` output file, ``-A`` capture from all devices, ``--devices`` a device list,
``--inject-descriptors``, ``--extcap-interfaces`` for listing hubs) but has not been run on this machine, because
USBPcap needs a driver install. Tests drive it through a fake executable. A mismatch shows up as the tool's own
usage text in the error, not as a silent empty capture.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

_ENV_OVERRIDE = "PACKETSNIFFER_MCP_USBPCAPCMD"
_DEFAULT_PATHS = (
    r"C:\Program Files\USBPcap\USBPcapCMD.exe",
    r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
)
_EXTCAP_INTERFACE = re.compile(r"\{value=([^}]*)\}\{display=([^}]*)\}")
_HUB_PATTERN = re.compile(r"^\\\\\.\\USBPcap\d+$")


class UsbPcapError(RuntimeError):
    """USBPcapCMD is missing or failed. ``error_type`` is machine-readable."""

    def __init__(self, message: str, error_type: str, suggestions: list[str] | None = None) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.suggestions = suggestions or []


def find_usbpcapcmd() -> str:
    """Locate USBPcapCMD.exe: env override, then PATH, then the default install folders."""
    candidates = [os.environ.get(_ENV_OVERRIDE), shutil.which("USBPcapCMD"), *_DEFAULT_PATHS]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise UsbPcapError(
        "USBPcapCMD.exe was not found",
        "missing_dependency",
        [
            "winget install desowin.USBPcap (installs a capture driver; needs administrator rights, may need a reboot)",
            f"Or set {_ENV_OVERRIDE} to the full path of USBPcapCMD.exe",
        ],
    )


def list_hubs(exe: str | None = None) -> list[dict[str, str]]:
    """USB root hubs USBPcap can capture on, via the extcap interface listing."""
    exe = exe or find_usbpcapcmd()
    proc = subprocess.run([exe, "--extcap-interfaces"], capture_output=True, text=True, timeout=20, check=False)  # noqa: S603
    if proc.returncode != 0:
        raise UsbPcapError(
            f"USBPcapCMD --extcap-interfaces failed (exit {proc.returncode}): {(proc.stderr or proc.stdout).strip()[:300]}",
            "capture_tool_failed",
        )
    hubs = [{"filter": v, "name": d} for v, d in _EXTCAP_INTERFACE.findall(proc.stdout)]
    if not hubs:
        raise UsbPcapError(
            "USBPcapCMD listed no USB root hubs",
            "no_hubs",
            ["Is the USBPcap driver installed and loaded? A reboot is sometimes needed after installing."],
        )
    return hubs


def capture(
    out_path: str,
    *,
    hub: str,
    seconds: int,
    devices: str | None = None,
    inject_descriptors: bool = False,
    exe: str | None = None,
) -> dict[str, object]:
    """Run USBPcapCMD for ``seconds`` and return the capture file's size.

    ``hub`` must look like ``\\\\.\\USBPcap1``. ``devices`` is a comma list of device addresses; without it the
    capture covers every device on the hub (``-A``). USBPcapCMD has no duration option, so it is terminated after
    ``seconds``; it flushes as it goes, so the file is complete up to that moment.
    """
    if not _HUB_PATTERN.match(hub):
        raise UsbPcapError(
            f"hub '{hub}' is not a USBPcap filter device",
            "invalid_hub",
            [r"Use the filter name from usb_list_hubs, e.g. \\.\USBPcap1"],
        )
    if devices is not None and not re.fullmatch(r"\d+(,\d+)*", devices):
        raise UsbPcapError("devices must be a comma list of numbers, e.g. '2,3'", "invalid_devices")
    exe = exe or find_usbpcapcmd()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = [exe, "-d", hub, "-o", str(out)]
    cmd += ["--devices", devices] if devices else ["-A"]
    if inject_descriptors:
        cmd.append("--inject-descriptors")

    started = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # noqa: S603
    try:
        proc.wait(timeout=seconds)
        exited_early = True
    except subprocess.TimeoutExpired:
        exited_early = False
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    stdout, stderr = proc.communicate()

    if exited_early and proc.returncode != 0:
        raise UsbPcapError(
            f"USBPcapCMD exited with code {proc.returncode}: {(stderr or stdout).strip()[:400]}",
            "capture_tool_failed",
            ["Run as administrator", "Check the hub name with usb_list_hubs"],
        )
    size = out.stat().st_size if out.exists() else 0
    if size < 24:
        raise UsbPcapError(
            "USBPcapCMD produced no capture file (or only an empty one)",
            "empty_capture",
            ["Run as administrator", "Check the hub name with usb_list_hubs", (stderr or stdout).strip()[:200]],
        )
    return {
        "path": str(out),
        "bytes": size,
        "seconds": round(time.monotonic() - started, 1),
        "ended": "tool exited on its own" if exited_early else "stopped after the requested duration",
        "command": " ".join(cmd),
    }
