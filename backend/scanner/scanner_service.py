"""Control and report NetShield WiFi scanner service state."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from pathlib import Path

from scanner.adapter_manager import read_adapter_status
from scanner.csv_logger import save_to_csv

_standalone_scanner_thread: threading.Thread | None = None
_standalone_scanner_stop_event = threading.Event()
_standalone_scanner_interface: str | None = None


SERVICE_NAME = "netshield-ml-scanner.service"
CAPTURE_SERVICE_NAME = "netshield-ml-capture.service"

SCANNER_STATUS_JSON = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "scan_results"
    / "scanner_status.json"
)


def _run_systemctl(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a systemctl command without prompting for a password."""

    return subprocess.run(
        ["sudo", "-n", "systemctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _service_exists() -> bool:
    """Return True when the scanner systemd unit is installed."""

    if shutil.which("systemctl") is None:
        return False

    result = subprocess.run(
        [
            "systemctl",
            "show",
            SERVICE_NAME,
            "--property=LoadState",
            "--value",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    return (
        result.returncode == 0
        and result.stdout.strip().lower() == "loaded"
    )



def _service_is_active(service_name: str) -> bool:
    """Return True when another protected NetShield service is active."""

    try:
        result = subprocess.run(
            [
                "systemctl",
                "is-active",
                service_name,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False

    return result.stdout.strip().lower() in {
        "active",
        "activating",
        "deactivating",
    }

def read_scanner_progress() -> dict:
    """Read live progress written by wifi_scanner.py."""

    empty = {
        "state": "idle",
        "interface": None,
        "sweep_number": 0,
        "current_channel": None,
        "channels_completed": 0,
        "total_channels": 0,
        "enabled_channels": [],
        "session_network_count": 0,
        "last_sweep_completed_at": None,
        "updated_at": None,
    }

    if not SCANNER_STATUS_JSON.exists():
        return empty

    try:
        payload = json.loads(
            SCANNER_STATUS_JSON.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return empty

    if not isinstance(payload, dict):
        return empty

    return {
        **empty,
        **payload,
    }


def read_scanner_status() -> dict:
    """Return scanner, service and adapter status."""

    adapter = read_adapter_status()
    progress = read_scanner_progress()

    if not _service_exists():
        global _standalone_scanner_thread
        is_running = _standalone_scanner_thread is not None and _standalone_scanner_thread.is_alive()
        state = "running" if is_running else ("not_detected" if not adapter["available"] else "idle")

        progress = {
            **progress,
            "state": state,
            "interface": _standalone_scanner_interface if is_running else None,
        }

        return {
            "state": state,
            "running": is_running,
            "interface": _standalone_scanner_interface if is_running else None,
            "message": "WiFi scanner is running." if is_running else ("Wireless adapter unavailable." if not adapter["available"] else "WiFi scanner is idle."),
            "adapter": adapter,
            "progress": progress,
        }

    result = subprocess.run(
        ["systemctl", "is-active", SERVICE_NAME],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    service_state = result.stdout.strip().lower()

    mapping = {
        "active": "running",
        "activating": "starting",
        "deactivating": "stopping",
        "inactive": "idle",
        "failed": "error",
    }

    state = mapping.get(service_state, "idle")

    running = state in {
        "starting",
        "running",
        "stopping",
    }

    if state == "idle":
        progress = {
            **progress,
            "state": "idle",
            "interface": None,
            "current_channel": None,
            "channels_completed": 0,
        }

    elif state in {"starting", "running"} and progress.get(
        "state"
    ) in {"idle", "stopping"}:
        progress = {
            **progress,
            "state": "starting",
            "interface": None,
            "current_channel": None,
        }

    elif state == "error":
        progress = {
            **progress,
            "state": "error",
            "current_channel": None,
        }

    interface = progress.get("interface") if running else None

    return {
        "state": state,
        "running": running,
        "interface": interface,
        "message": {
            "starting": "WiFi scanner is starting.",
            "running": "WiFi scanner is running.",
            "stopping": "WiFi scanner is stopping.",
            "idle": "WiFi scanner is idle.",
            "error": "WiFi scanner encountered an error.",
        }.get(state, "WiFi scanner is idle."),
        "adapter": adapter,
        "progress": progress,
    }


def _scan_windows_networks() -> dict[str, dict[str, str | int | None]]:
    if shutil.which("netsh") is None:
        return {}
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return {}

    if result.returncode != 0:
        return {}

    networks = {}
    cur = None
    lines = result.stdout.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("SSID ") and not line.startswith("SSID name"):
            cur_ssid = line.split(":", 1)[1].strip() if ":" in line else "<hidden>"
            cur = {"SSID": cur_ssid or "<hidden>", "Encryption": "Open"}
        elif line.startswith("Authentication") and cur:
            cur["Encryption"] = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID ") and cur:
            bssid = line.split(":", 1)[1].strip().upper()
            ap = dict(cur)
            ap["BSSID"] = bssid
            ap["Channel"] = None
            ap["Signal"] = None
            networks[bssid] = ap
        elif line.startswith("Signal") and networks:
            sig = line.split(":", 1)[1].strip().replace("%", "")
            try:
                pct = int(sig)
                dbm = int((pct / 2) - 100)
                list(networks.values())[-1]["Signal"] = dbm
            except ValueError:
                pass
        elif line.startswith("Channel") and networks:
            try:
                ch = int(line.split(":", 1)[1].strip())
                list(networks.values())[-1]["Channel"] = ch
                freq = f"{2407 + ch*5} MHz" if ch <= 14 else (f"{5000 + ch*5} MHz" if ch <= 177 else "Unknown")
                list(networks.values())[-1]["Frequency"] = freq
            except ValueError:
                pass

    return networks


def _write_scanner_status_file(state: str, interface: str | None = None, **extra):
    status_path = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "scan_results"
        / "scanner_status.json"
    )
    status_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "state": state,
        "interface": interface,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        **extra,
    }
    tmp_path = status_path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp_path.replace(status_path)


def _standalone_scan_loop(interface: str):
    global _standalone_scanner_interface
    _standalone_scanner_interface = interface
    known_networks = {}
    csv_path = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "scan_results"
        / "wifi_scan_results.csv"
    )

    sweep = 0
    while not _standalone_scanner_stop_event.is_set():
        sweep += 1
        latest = _scan_windows_networks()
        for bssid, details in latest.items():
            known_networks[bssid] = details

        if known_networks:
            save_to_csv(known_networks, csv_path)

        first_ap = next(iter(latest.values())) if latest else {}
        _write_scanner_status_file(
            state="running",
            interface=interface,
            sweep_number=sweep,
            current_channel=first_ap.get("Channel"),
            channels_completed=11,
            total_channels=11,
            enabled_channels=list(range(1, 12)),
            session_network_count=len(known_networks),
            last_sweep_completed_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        time.sleep(3)

    _write_scanner_status_file(
        state="idle",
        interface=None,
        sweep_number=sweep,
        current_channel=None,
        channels_completed=0,
        total_channels=11,
        enabled_channels=list(range(1, 12)),
        session_network_count=len(known_networks),
        last_sweep_completed_at=time.strftime("%Y-%m-%d %H:%M:%S"),
    )


def start_scanner(interface: str | None) -> tuple[dict, int]:
    """Start scanning when an adapter and service are available."""

    if _service_is_active(CAPTURE_SERVICE_NAME):
        return {
            "ok": False,
            "state": "service_conflict",
            "message": (
                "Stop packet capture before starting WiFi scanning."
            ),
        }, 409

    adapter = read_adapter_status()

    if not adapter["available"]:
        return {
            "ok": False,
            "state": "not_detected",
            "message": adapter["message"],
        }, 409

    interfaces = [
        item["name"]
        for item in adapter["interfaces"]
    ]

    selected_interface = interface or interfaces[0]

    if selected_interface not in interfaces:
        return {
            "ok": False,
            "state": "invalid_interface",
            "message": (
                f"Wireless interface '{selected_interface}' "
                "is not available."
            ),
        }, 400

    current = read_scanner_status()

    if current["running"]:
        return {
            "ok": False,
            "state": current["state"],
            "message": "WiFi scanner is already running.",
            "scanner": current,
        }, 409

    if not _service_exists():
        global _standalone_scanner_thread, _standalone_scanner_stop_event
        _standalone_scanner_stop_event.clear()
        _standalone_scanner_thread = threading.Thread(
            target=_standalone_scan_loop,
            args=(selected_interface,),
            daemon=True,
        )
        _standalone_scanner_thread.start()
        time.sleep(0.5)

        return {
            "ok": True,
            "scanner": read_scanner_status(),
        }, 202

    result = _run_systemctl(
        ["start", SERVICE_NAME]
    )

    if result.returncode != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                result.stderr.strip()
                or result.stdout.strip()
                or "Unable to start WiFi scanner."
            ),
        }, 500

    return {
        "ok": True,
        "scanner": read_scanner_status(),
    }, 202


def stop_scanner() -> tuple[dict, int]:
    """Stop the WiFi scanner safely."""

    current = read_scanner_status()

    if not current["running"]:
        return {
            "ok": True,
            "scanner": current,
            "message": "WiFi scanner is already stopped.",
        }, 200

    if not _service_exists():
        global _standalone_scanner_stop_event
        _standalone_scanner_stop_event.set()
        time.sleep(0.5)

        return {
            "ok": True,
            "scanner": read_scanner_status(),
        }, 200

    result = _run_systemctl(
        ["stop", SERVICE_NAME]
    )

    if result.returncode != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                result.stderr.strip()
                or result.stdout.strip()
                or "Unable to stop WiFi scanner."
            ),
        }, 500

    return {
        "ok": True,
        "scanner": read_scanner_status(),
    }, 200

