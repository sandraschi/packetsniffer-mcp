"""USBPcapCMD wrapper tests, driven through a fake executable (no USBPcap driver on this machine).

These prove the orchestration: argument building, duration handling, error surfacing. They cannot prove the real
USBPcapCMD accepts these arguments; that needs a machine with USBPcap installed.
"""

import os
import stat
import sys
import textwrap

import pytest

from packetsniffer_mcp.capture import ops, usbpcapcmd
from packetsniffer_mcp.capture.pcapfile import read_records
from tests.capture_builders import usb_frame

FAKE_SCRIPT = textwrap.dedent(
    """
    import os, struct, sys, time

    args = sys.argv[1:]
    mode = os.environ.get("FAKE_USBPCAPCMD", "run")
    log = os.environ.get("FAKE_USBPCAPCMD_LOG")
    if log:
        open(log, "w").write(" ".join(args))
    if "--extcap-interfaces" in args:
        if mode == "nohubs":
            sys.exit(0)
        print("extcap {version=1.5.4.0}")
        print(r"interface {value=\\\\.\\USBPcap1}{display=USBPcap1}")
        print(r"interface {value=\\\\.\\USBPcap2}{display=USBPcap2}")
        sys.exit(0)
    if mode == "fail":
        sys.stderr.write("Usage: USBPcapCMD [options]\\n")
        sys.exit(2)
    out = args[args.index("-o") + 1]
    if mode == "silent":
        sys.exit(0)
    head = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
    frame = struct.pack("<HQIHBHHBBI", 27, 1, 0, 9, 0, 1, 2, 2, 3, 2) + b"\\x1b\\x41"
    with open(out, "wb") as f:
        f.write(head + struct.pack("<IIII", 1000, 0, len(frame), len(frame)) + frame)
    if mode == "run":
        time.sleep(60)
    """
)


@pytest.fixture
def fake_exe(tmp_path, monkeypatch):
    script = tmp_path / "fake_usbpcapcmd.py"
    script.write_text(FAKE_SCRIPT, encoding="utf-8")
    if os.name == "nt":
        exe = tmp_path / "USBPcapCMD.cmd"
        exe.write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        exe = tmp_path / "USBPcapCMD"
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PACKETSNIFFER_MCP_USBPCAPCMD", str(exe))
    monkeypatch.setenv("FAKE_USBPCAPCMD_LOG", str(tmp_path / "args.txt"))
    return exe


def test_list_hubs_parses_extcap_interfaces(fake_exe):
    result = ops.usb_list_hubs()
    assert result["success"]
    assert result["data"]["hubs"] == [
        {"filter": "\\\\.\\USBPcap1", "name": "USBPcap1"},
        {"filter": "\\\\.\\USBPcap2", "name": "USBPcap2"},
    ]


def test_list_hubs_with_no_output_is_an_error_not_an_empty_success(fake_exe, monkeypatch):
    monkeypatch.setenv("FAKE_USBPCAPCMD", "nohubs")
    result = ops.usb_list_hubs()
    assert not result["success"] and result["error_type"] == "no_hubs"


def test_capture_runs_for_the_duration_then_terminates_and_the_file_is_readable(fake_exe, tmp_path):
    out = tmp_path / "cap" / "02-dot.pcap"
    result = ops.usb_capture(str(out), hub="\\\\.\\USBPcap1", seconds=2, devices=None, inject_descriptors=False)
    assert result["success"], result
    assert result["data"]["ended"] == "stopped after the requested duration"
    args = (tmp_path / "args.txt").read_text()
    assert "-d \\\\.\\USBPcap1" in args and f"-o {out}" in args and args.endswith("-A")
    _fmt, records = read_records(out)
    assert len(records) == 1 and records[0].data == usb_frame(device=2, endpoint=2, data=b"\x1b\x41")
    payloads = ops.usb_payloads(str(out))["data"]["transfers"]
    assert [p["hex"] for p in payloads] == ["1b 41"]


def test_capture_passes_device_list_and_inject_flag(fake_exe, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_USBPCAPCMD", "once")
    out = tmp_path / "c.pcap"
    result = ops.usb_capture(str(out), hub="\\\\.\\USBPcap1", seconds=10, devices="2,3", inject_descriptors=True)
    assert result["success"] and result["data"]["ended"] == "tool exited on its own"
    args = (tmp_path / "args.txt").read_text()
    assert "--devices 2,3" in args and "--inject-descriptors" in args and " -A" not in args


def test_capture_surfaces_the_tools_own_error_text(fake_exe, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_USBPCAPCMD", "fail")
    result = ops.usb_capture(
        str(tmp_path / "x.pcap"), hub="\\\\.\\USBPcap1", seconds=5, devices=None, inject_descriptors=False
    )
    assert not result["success"] and result["error_type"] == "capture_tool_failed" and "Usage" in result["error"]


def test_capture_that_writes_nothing_is_an_error(fake_exe, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_USBPCAPCMD", "silent")
    result = ops.usb_capture(
        str(tmp_path / "x.pcap"), hub="\\\\.\\USBPcap1", seconds=5, devices=None, inject_descriptors=False
    )
    assert not result["success"] and result["error_type"] == "empty_capture"


@pytest.mark.parametrize(
    ("kwargs", "error_type"),
    [
        ({"hub": "COM3", "devices": None}, "invalid_hub"),
        ({"hub": "\\\\.\\USBPcap1; calc", "devices": None}, "invalid_hub"),
        ({"hub": "\\\\.\\USBPcap1", "devices": "2;calc"}, "invalid_devices"),
    ],
)
def test_capture_rejects_unsafe_arguments_before_running_anything(fake_exe, tmp_path, kwargs, error_type):
    result = ops.usb_capture(str(tmp_path / "x.pcap"), seconds=1, inject_descriptors=False, **kwargs)
    assert not result["success"] and result["error_type"] == error_type
    assert not (tmp_path / "args.txt").exists(), "the tool must not have been started"


def test_missing_usbpcapcmd_is_a_clean_missing_dependency_error(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETSNIFFER_MCP_USBPCAPCMD", str(tmp_path / "nope.exe"))
    monkeypatch.setattr(usbpcapcmd.shutil, "which", lambda _name: None)
    monkeypatch.setattr(usbpcapcmd, "_DEFAULT_PATHS", ())
    result = ops.usb_list_hubs()
    assert not result["success"] and result["error_type"] == "missing_dependency"
    assert any("desowin.USBPcap" in s for s in result["suggestions"])


def test_capture_requires_a_hub_and_a_save_path():
    assert (
        ops.usb_capture(None, hub="\\\\.\\USBPcap1", seconds=1, devices=None, inject_descriptors=False)["error_type"]
        == "invalid_request"
    )
    assert (
        ops.usb_capture("x.pcap", hub=None, seconds=1, devices=None, inject_descriptors=False)["error_type"]
        == "invalid_request"
    )
