"""Real-time WiFi network scanner for Kali Linux.

Run with root privileges on a wireless adapter that supports monitor mode:
    sudo python3 scanner/wifi_scanner.py --interface wlan0
"""

from __future__ import annotations

import argparse
import json
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from scapy.all import AsyncSniffer, conf

from csv_logger import save_to_csv
from network_parser import extract_network_details


DEFAULT_CSV_PATH = Path("backend/data/scan_results/wifi_scan_results.csv")
DEFAULT_CHANNELS_2GHZ = list(range(1, 12))
CHANNEL_DWELL_SECONDS = 1.5

def _run_command(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
def set_channel(interface: str, channel: int) -> bool:
    """Switch the wireless interface to a WiFi channel."""
    result = _run_command(
        ["iwconfig", interface, "channel", str(channel)],
        check=False,
    )

    if result.returncode != 0:
        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
            or "unknown channel-switch error"
        )

        print(
            f"Warning: unable to switch {interface} "
            f"to channel {channel}: {error_message}",
            file=sys.stderr,
            flush=True,
        )
        return False

    return True


def get_enabled_channels(interface: str) -> list[int]:
    """Return enabled WiFi channels reported by Linux for this adapter."""
    try:
        interface_info = _run_command(
            ["iw", "dev", interface, "info"]
        )
    except subprocess.CalledProcessError:
        return DEFAULT_CHANNELS_2GHZ.copy()

    phy_name = None

    for raw_line in interface_info.stdout.splitlines():
        line = raw_line.strip()

        if line.startswith("wiphy "):
            phy_number = line.split(" ", 1)[1].strip()
            phy_name = f"phy{phy_number}"
            break

    if not phy_name:
        return DEFAULT_CHANNELS_2GHZ.copy()

    try:
        phy_info = _run_command(
            ["iw", "phy", phy_name, "info"]
        )
    except subprocess.CalledProcessError:
        return DEFAULT_CHANNELS_2GHZ.copy()

    channels: list[int] = []

    for raw_line in phy_info.stdout.splitlines():
        line = raw_line.strip()

        if "MHz [" not in line:
            continue

        if "(disabled)" in line.lower():
            continue

        try:
            channel_text = (
                line.split("[", 1)[1]
                .split("]", 1)[0]
                .strip()
            )
            channel = int(channel_text)
        except (IndexError, ValueError):
            continue

        if channel not in channels:
            channels.append(channel)

    return channels or DEFAULT_CHANNELS_2GHZ.copy()


def _require_command(command_name: str) -> None:
    if shutil.which(command_name) is None:
        raise RuntimeError(f"Required command not found: {command_name}")


def enable_monitor_mode(interface: str) -> str:
    """Enable monitor mode using airmon-ng and return the monitor interface name."""

    for command_name in ("iwconfig", "airmon-ng", "iw"):
        _require_command(command_name)

    try:
        _run_command(["airmon-ng", "check", "kill"], check=False)
        result = _run_command(["airmon-ng", "start", interface])
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Could not enable monitor mode for {interface}: {exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc

    monitor_interface = _parse_monitor_interface(result.stdout, interface)
    _verify_monitor_mode(monitor_interface)
    return monitor_interface


def _parse_monitor_interface(airmon_output: str, interface: str) -> str:
    for line in airmon_output.splitlines():
        if "monitor mode" in line.lower() and "enabled" in line.lower():
            tokens = line.replace(")", " ").replace("(", " ").split()
            for token in reversed(tokens):
                if token.startswith(interface) and token != interface:
                    return token

    candidate = f"{interface}mon"
    if _interface_exists(candidate):
        return candidate
    return interface


def _interface_exists(interface: str) -> bool:
    try:
        _run_command(["iwconfig", interface])
        return True
    except subprocess.CalledProcessError:
        return False


def _verify_monitor_mode(interface: str) -> None:
    try:
        result = _run_command(["iwconfig", interface])
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Could not verify interface {interface}: {exc.stderr.strip()}") from exc

    if "mode:monitor" not in result.stdout.lower().replace(" ", ""):
        raise RuntimeError(f"Interface {interface} is not in monitor mode.")


def restore_managed_mode(interface: str) -> None:
    """Disable monitor mode and restart normal WiFi services."""
    result = _run_command(
        ["airmon-ng", "stop", interface],
        check=False,
    )

    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        print(
            f"Warning: could not restore {interface}: {details}",
            file=sys.stderr,
        )

    # airmon-ng check kill may stop these normal WiFi services.
    _run_command(
        ["systemctl", "start", "NetworkManager"],
        check=False,
    )
    _run_command(
        ["systemctl", "start", "wpa_supplicant"],
        check=False,
    )


def scan_networks(
    interface: str,
    stop_check=None,
    channels: list[int] | None = None,
    progress_callback=None,
) -> dict[str, dict[str, str | int | None]]:
    """Scan enabled WiFi channels and return discovered access points."""

    networks: dict[str, dict[str, str | int | None]] = {}
    scan_channels = channels or get_enabled_channels(interface)
    total_channels = len(scan_channels)

    def handle_packet(packet: Any) -> None:
        details = extract_network_details(packet)
        if details is None:
            return
        networks[details.bssid] = details.as_dict()

    for channel_index, channel in enumerate(
        scan_channels,
        start=1,
    ):
        if stop_check and stop_check():
            break

        if not set_channel(interface, channel):
            if progress_callback:
                progress_callback(
                    channel,
                    channel_index,
                    total_channels,
                    set(networks),
                )
            continue

        if progress_callback:
            progress_callback(
                channel,
                channel_index - 1,
                total_channels,
                set(networks),
            )

        sniffer = AsyncSniffer(
            iface=interface,
            prn=handle_packet,
            store=False,
        )

        try:
            sniffer.start()

            dwell_deadline = (
                time.monotonic() + CHANNEL_DWELL_SECONDS
            )

            while time.monotonic() < dwell_deadline:
                if stop_check and stop_check():
                    break

                remaining = dwell_deadline - time.monotonic()
                time.sleep(min(0.1, max(remaining, 0)))
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass

        if progress_callback:
            progress_callback(
                channel,
                channel_index,
                total_channels,
                set(networks),
            )

        if stop_check and stop_check():
            break

    return networks


def _write_scanner_status(
    status_path: Path,
    **values,
) -> None:
    """Atomically save runtime scanner progress for the API."""
    status_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        **values,
    }

    temporary_path = status_path.with_suffix(
        status_path.suffix + ".tmp"
    )

    temporary_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    temporary_path.replace(status_path)


def _merge_networks(
    known_networks: dict[str, dict[str, str | int | None]],
    latest_networks: dict[str, dict[str, str | int | None]],
) -> None:
    for bssid, details in latest_networks.items():
        known_networks[bssid] = details


def _format_value(value: str | int | None, default: str = "Unknown") -> str:
    if value is None or value == "":
        return default
    return str(value)


def _print_table(networks: dict[str, dict[str, str | int | None]]) -> None:
    headers = ["SSID", "BSSID", "Channel", "Frequency", "Signal", "Encryption"]
    rows = [
        [
            _format_value(network.get("SSID"), "<hidden>"),
            _format_value(network.get("BSSID")),
            _format_value(network.get("Channel")),
            _format_value(network.get("Frequency")),
            _format_value(network.get("Signal")),
            _format_value(network.get("Encryption")),
        ]
        for network in sorted(
            networks.values(),
            key=lambda item: (item.get("Signal") is None, -(item.get("Signal") or -999)),
        )
    ]

    widths = [
        max(len(header), *(len(row[index]) for row in rows)) if rows else len(header)
        for index, header in enumerate(headers)
    ]

    line = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    header_line = "| " + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)) + " |"

    print("\033c", end="")
    print("WiFi Real-Time Security and Signal Analyzer - Network Scanner")
    print(f"Last update: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(line)
    print(header_line)
    print(line)

    if not rows:
        print("| " + "No networks detected yet.".ljust(sum(widths) + (3 * (len(headers) - 1))) + " |")
    else:
        for row in rows:
            print("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |")

    print(line)
    print(f"Networks detected: {len(networks)}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Real-time WiFi Network Scanner for Kali Linux")
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Wireless adapter name, for example wlan0. Monitor mode will be enabled automatically.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_CSV_PATH),
        help=f"CSV output path. Default: {DEFAULT_CSV_PATH}",
    )
    parser.add_argument(
        "--no-monitor-setup",
        action="store_true",
        help="Skip airmon-ng setup when the provided interface is already in monitor mode.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    known_networks: dict[str, dict[str, str | int | None]] = {}
    stop_requested = False
    monitor_interface: str | None = None
    monitor_mode_created = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    try:
        conf.verb = 0

        if args.no_monitor_setup:
            monitor_interface = args.interface
        else:
            monitor_interface = enable_monitor_mode(args.interface)
            monitor_mode_created = True

        print(f"Scanning on monitor interface: {monitor_interface}")

        scan_channels = get_enabled_channels(monitor_interface)
        status_path = (
            Path(args.output).parent
            / "scanner_status.json"
        )
        sweep_number = 0
        last_sweep_completed_at = None

        _write_scanner_status(
            status_path,
            state="scanning",
            interface=monitor_interface,
            sweep_number=0,
            current_channel=None,
            channels_completed=0,
            total_channels=len(scan_channels),
            enabled_channels=scan_channels,
            session_network_count=0,
            last_sweep_completed_at=None,
        )

        while not stop_requested:
            sweep_number += 1

            def update_progress(
                channel,
                channels_completed,
                total_channels,
                sweep_bssids,
            ):
                _write_scanner_status(
                    status_path,
                    state="scanning",
                    interface=monitor_interface,
                    sweep_number=sweep_number,
                    current_channel=channel,
                    channels_completed=channels_completed,
                    total_channels=total_channels,
                    enabled_channels=scan_channels,
                    session_network_count=len(
                        set(known_networks) | set(sweep_bssids)
                    ),
                    last_sweep_completed_at=(
                        last_sweep_completed_at
                    ),
                )

            latest_networks = scan_networks(
                monitor_interface,
                stop_check=lambda: stop_requested,
                channels=scan_channels,
                progress_callback=update_progress,
            )

            _merge_networks(known_networks, latest_networks)
            save_to_csv(known_networks, args.output)

            if not stop_requested:
                last_sweep_completed_at = time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

            _write_scanner_status(
                status_path,
                state=(
                    "stopping"
                    if stop_requested
                    else "scanning"
                ),
                interface=monitor_interface,
                sweep_number=sweep_number,
                current_channel=None,
                channels_completed=(
                    0
                    if stop_requested
                    else len(scan_channels)
                ),
                total_channels=len(scan_channels),
                enabled_channels=scan_channels,
                session_network_count=len(known_networks),
                last_sweep_completed_at=(
                    last_sweep_completed_at
                ),
            )

            _print_table(known_networks)

    except PermissionError:
        print(
            "Permission denied. Run this scanner with sudo/root privileges.",
            file=sys.stderr,
        )
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1
    finally:
        if monitor_mode_created and monitor_interface:
            print(
                f"Restoring {monitor_interface} to managed mode..."
            )
            restore_managed_mode(monitor_interface)

    print("\nScanner stopped. Latest CSV saved successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
