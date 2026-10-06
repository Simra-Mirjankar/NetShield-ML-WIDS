"""Wireless adapter detection for NetShield."""

from __future__ import annotations

import shutil
import subprocess


def read_adapter_status() -> dict:
    """Return available Linux wireless interfaces."""

    if shutil.which("iw") is None:
        if shutil.which("netsh") is not None:
            return _read_windows_adapter_status()
        return {
            "available": False,
            "state": "command_missing",
            "interfaces": [],
            "message": "The iw command is not installed.",
        }

    try:
        result = subprocess.run(
            ["iw", "dev"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "available": False,
            "state": "error",
            "interfaces": [],
            "message": f"Unable to inspect wireless interfaces: {exc}",
        }

    if result.returncode != 0:
        return {
            "available": False,
            "state": "error",
            "interfaces": [],
            "message": (
                result.stderr.strip()
                or "Unable to inspect wireless interfaces."
            ),
        }

    interfaces = []
    current = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()

        if line.startswith("Interface "):
            if current:
                interfaces.append(current)

            current = {
                "name": line.split(" ", 1)[1].strip(),
                "mode": "unknown",
                "channel": None,
            }

        elif current and line.startswith("type "):
            current["mode"] = line.split(" ", 1)[1].strip()

        elif current and line.startswith("channel "):
            parts = line.split()

            if len(parts) >= 2:
                try:
                    current["channel"] = int(parts[1])
                except ValueError:
                    current["channel"] = None

    if current:
        interfaces.append(current)

    if not interfaces:
        return {
            "available": False,
            "state": "not_detected",
            "interfaces": [],
            "message": "No wireless interface was detected.",
        }

    return {
        "available": True,
        "state": "ready",
        "interfaces": interfaces,
        "message": f"{len(interfaces)} wireless interface(s) detected.",
    }


def _read_windows_adapter_status() -> dict:
    """Return available Windows wireless interfaces via netsh."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "available": False,
            "state": "error",
            "interfaces": [],
            "message": f"Unable to inspect wireless interfaces: {exc}",
        }

    if result.returncode != 0:
        return {
            "available": False,
            "state": "error",
            "interfaces": [],
            "message": result.stderr.strip() or "Unable to inspect wireless interfaces.",
        }

    interfaces = []
    current = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Name"):
            parts = line.split(":", 1)
            if len(parts) >= 2:
                if current:
                    interfaces.append(current)
                current = {
                    "name": parts[1].strip(),
                    "mode": "managed",
                    "channel": None,
                }
        elif current and line.startswith("Channel"):
            parts = line.split(":", 1)
            if len(parts) >= 2:
                try:
                    current["channel"] = int(parts[1].strip())
                except ValueError:
                    current["channel"] = None

    if current:
        interfaces.append(current)

    if not interfaces:
        return {
            "available": False,
            "state": "not_detected",
            "interfaces": [],
            "message": "No wireless interface was detected.",
        }

    return {
        "available": True,
        "state": "ready",
        "interfaces": interfaces,
        "message": f"{len(interfaces)} wireless interface(s) detected.",
    }

