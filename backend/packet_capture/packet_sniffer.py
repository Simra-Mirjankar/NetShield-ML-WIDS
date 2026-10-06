"""Live 802.11 packet capture for Kali Linux monitor-mode interfaces.

Run:
    sudo python3 packet_capture/packet_sniffer.py --interface wlan0mon
"""

from __future__ import annotations

import argparse
import json
import shutil
import signal
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque

from scapy.all import conf, sniff

from packet_analyzer import PacketAnalysis, PacketAnalyzer
from packet_logger import PacketCSVLogger

try:
    from ml.live_inference import LiveInferenceBuffer
except ImportError:
    backend_dir = Path(__file__).resolve().parents[1]
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))
    try:
        from ml.live_inference import LiveInferenceBuffer
    except ImportError:
        from backend.ml.live_inference import LiveInferenceBuffer


DEFAULT_OUTPUT = Path("backend/data/packet_logs/wifi_packets.csv")
MAX_VISIBLE_ROWS = 20
STATUS_WRITE_INTERVAL_SECONDS = 1.0
DEFAULT_CHANNELS_2GHZ = list(range(1, 12))
CHANNEL_DWELL_SECONDS = 2.0


def _run_command(
    command: list[str],
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def set_channel(interface: str, channel: int) -> bool:
    """Switch a monitor-mode interface to a WiFi channel."""
    result = _run_command(
        ["iwconfig", interface, "channel", str(channel)],
        check=False,
    )

    if result.returncode != 0:
        details = (
            result.stderr.strip()
            or result.stdout.strip()
            or "unknown channel-switch error"
        )

        print(
            f"Warning: unable to switch {interface} "
            f"to channel {channel}: {details}",
            file=sys.stderr,
            flush=True,
        )
        return False

    return True


def get_enabled_channels(interface: str) -> list[int]:
    """Return enabled WiFi channels reported by Linux."""
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

    channels = []

    for raw_line in phy_info.stdout.splitlines():
        line = raw_line.strip()

        if "MHz" not in line or "[" not in line or "]" not in line:
            continue

        if "(disabled)" in line:
            continue

        try:
            channel_text = line.split("[", 1)[1].split("]", 1)[0]
            channel = int(channel_text)
        except (IndexError, ValueError):
            continue

        if channel not in channels:
            channels.append(channel)

    return channels or DEFAULT_CHANNELS_2GHZ.copy()


def _require_command(command_name: str) -> None:
    if shutil.which(command_name) is None:
        raise RuntimeError(
            f"Required command not found: {command_name}"
        )


def _interface_exists(interface: str) -> bool:
    try:
        _run_command(["iwconfig", interface])
        return True
    except subprocess.CalledProcessError:
        return False


def _parse_monitor_interface(
    airmon_output: str,
    interface: str,
) -> str:
    for line in airmon_output.splitlines():
        lowered_line = line.lower()

        if "monitor mode" in lowered_line and "enabled" in lowered_line:
            tokens = (
                line.replace(")", " ")
                .replace("(", " ")
                .split()
            )

            for token in reversed(tokens):
                if token.startswith(interface) and token != interface:
                    return token

    candidate = f"{interface}mon"

    if _interface_exists(candidate):
        return candidate

    return interface


def _verify_monitor_mode(interface: str) -> None:
    try:
        result = _run_command(["iwconfig", interface])
    except subprocess.CalledProcessError as command_error:
        raise RuntimeError(
            f"Could not verify interface {interface}: "
            f"{command_error.stderr.strip()}"
        ) from command_error

    normalized_output = result.stdout.lower().replace(" ", "")

    if "mode:monitor" not in normalized_output:
        raise RuntimeError(
            f"Interface {interface} is not in monitor mode."
        )


def enable_monitor_mode(interface: str) -> str:
    """Enable monitor mode and return the monitor interface name."""
    for command_name in ("iwconfig", "airmon-ng", "iw"):
        _require_command(command_name)

    _run_command(
        ["airmon-ng", "check", "kill"],
        check=False,
    )

    try:
        result = _run_command(
            ["airmon-ng", "start", interface]
        )
    except subprocess.CalledProcessError as command_error:
        details = (
            command_error.stderr.strip()
            or command_error.stdout.strip()
        )

        raise RuntimeError(
            f"Could not enable monitor mode for {interface}: {details}"
        ) from command_error

    monitor_interface = _parse_monitor_interface(
        result.stdout,
        interface,
    )
    _verify_monitor_mode(monitor_interface)

    return monitor_interface


def restore_managed_mode(interface: str) -> None:
    """Disable monitor mode and restart normal WiFi services."""
    try:
        result = _run_command(
            ["airmon-ng", "stop", interface],
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        print(
            f"Warning: restoring {interface} timed out after 15 seconds.",
            file=sys.stderr,
        )
    else:
        if result.returncode != 0:
            details = result.stderr.strip() or result.stdout.strip()
            print(
                f"Warning: could not restore {interface}: {details}",
                file=sys.stderr,
            )

    for service_name in ("NetworkManager", "wpa_supplicant"):
        try:
            _run_command(
                ["systemctl", "start", service_name],
                check=False,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            print(
                f"Warning: starting {service_name} timed out.",
                file=sys.stderr,
            )


def write_capture_error_status(
    output_path: str | Path,
    interface: str,
    error_message: str,
) -> None:
    """Persist a capture failure so the API can explain it."""
    status_path = (
        Path(output_path).parent
        / "capture_status.json"
    )

    try:
        status_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = {
            "state": "error",
            "interface": interface,
            "last_error": error_message,
            "updated_at": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }

        temporary_path = status_path.with_suffix(
            status_path.suffix + ".tmp"
        )

        temporary_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

        temporary_path.replace(status_path)

    except OSError as status_error:
        print(
            "Warning: unable to save capture error status: "
            f"{status_error}",
            file=sys.stderr,
        )


class LivePacketMonitor:
    """Coordinate packet sniffing, analysis, logging, and terminal output."""

    def __init__(
        self,
        interface: str,
        output_path: str | Path,
    ) -> None:
        self.interface = interface
        self.stop_requested = False
        self.analyzer = PacketAnalyzer()
        self.output_path = Path(output_path)
        self.logger = PacketCSVLogger(self.output_path)
        self.status_path = (
            self.output_path.parent / "capture_status.json"
        )
        self.recent_packets: Deque[PacketAnalysis] = deque(
            maxlen=MAX_VISIBLE_ROWS
        )
        self.packet_count = 0
        self.packet_type_counts: dict[str, int] = {}
        self.started_at = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.started_monotonic = time.monotonic()
        self.last_packet_at: str | None = None
        self._last_status_write = 0.0

        self.enabled_channels = get_enabled_channels(
            self.interface
        )
        self.current_channel: int | None = None
        self.channel_index = 0
        self.sweep_number = 0
        self.inference_buffer = LiveInferenceBuffer()

    def start(self) -> None:
        print(
            f"Starting live packet capture on {self.interface}. "
            "Press Ctrl+C to stop."
        )

        self._write_runtime_status(
            state="capturing",
            force=True,
        )

        while not self.stop_requested:
            self.sweep_number += 1

            for index, channel in enumerate(
                self.enabled_channels,
                start=1,
            ):
                if self.stop_requested:
                    break

                self.channel_index = index

                if not set_channel(
                    self.interface,
                    channel,
                ):
                    continue

                self.current_channel = channel

                self._write_runtime_status(
                    state="capturing",
                    force=True,
                )

                dwell_deadline = (
                    time.monotonic()
                    + CHANNEL_DWELL_SECONDS
                )

                while (
                    not self.stop_requested
                    and time.monotonic()
                    < dwell_deadline
                ):
                    remaining = (
                        dwell_deadline
                        - time.monotonic()
                    )

                    sniff(
                        iface=self.interface,
                        prn=self._handle_packet,
                        store=False,
                        timeout=min(
                            1.0,
                            max(remaining, 0.05),
                        ),
                    )

                    self._write_runtime_status(
                        state="capturing",
                    )

        self._write_runtime_status(
            state="stopping",
            force=True,
        )

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_requested = True

    def _write_runtime_status(
        self,
        state: str,
        force: bool = False,
    ) -> None:
        """Atomically save lightweight live capture progress."""
        now_monotonic = time.monotonic()

        if (
            not force
            and (
                now_monotonic - self._last_status_write
                < STATUS_WRITE_INTERVAL_SECONDS
            )
        ):
            return

        self.status_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        elapsed_seconds = max(
            0.0,
            time.monotonic() - self.started_monotonic,
        )

        packet_rate = (
            self.packet_count / elapsed_seconds
            if elapsed_seconds > 0
            else 0.0
        )

        payload = {
            "state": state,
            "interface": self.interface,
            "last_error": "",
            "packet_count": self.packet_count,
            "session_start_row": (
                self.logger.session_start_row
            ),
            "packet_rate": round(packet_rate, 2),
            "elapsed_seconds": round(
                elapsed_seconds,
                1,
            ),
            "packet_type_counts": dict(
                sorted(self.packet_type_counts.items())
            ),
            "started_at": self.started_at,
            "last_packet_at": self.last_packet_at,
            "current_channel": self.current_channel,
            "channel_index": self.channel_index,
            "total_channels": len(
                self.enabled_channels
            ),
            "enabled_channels": (
                self.enabled_channels
            ),
            "sweep_number": self.sweep_number,
            "updated_at": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }

        temporary_path = self.status_path.with_suffix(
            self.status_path.suffix + ".tmp"
        )

        temporary_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

        temporary_path.replace(self.status_path)
        self._last_status_write = now_monotonic

    def _handle_packet(self, packet: Any) -> None:
        analysis = self.analyzer.analyze_packet(
            packet,
            capture_channel=self.current_channel,
        )

        if analysis is None:
            return

        self.logger.log_packet(analysis)

        self.packet_count += 1

        self.packet_type_counts[analysis.packet_type] = (
            self.packet_type_counts.get(
                analysis.packet_type,
                0,
            )
            + 1
        )

        self.last_packet_at = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self._write_runtime_status(
            state="capturing",
        )

        self.recent_packets.append(analysis)
        self._print_live_table()

        result = self.inference_buffer.add_packet(analysis)
        if result is not None:
            attack_prob = result.get("attack_probability")
            normal_prob = result.get("normal_probability")
            attack_str = (
                f"{attack_prob:.4f}"
                if isinstance(attack_prob, (int, float))
                else str(attack_prob)
            )
            normal_str = (
                f"{normal_prob:.4f}"
                if isinstance(normal_prob, (int, float))
                else str(normal_prob)
            )
            print(
                f"[ML Inference] Prediction: {result.get('prediction')} | "
                f"Label: {result.get('label')} | "
                f"Attack Prob: {attack_str} | "
                f"Normal Prob: {normal_str} | "
                f"Total Packets: {result.get('total_packets')}",
                flush=True,
            )

    def _print_live_table(self) -> None:
        headers = [
            "Timestamp",
            "Packet Type",
            "Source MAC",
            "Destination MAC",
            "Signal",
        ]

        rows = [
            [
                analysis.timestamp,
                analysis.packet_type,
                analysis.source_mac,
                analysis.destination_mac,
                (
                    str(analysis.signal_strength)
                    if analysis.signal_strength is not None
                    else "-"
                ),
            ]
            for analysis in self.recent_packets
        ]

        widths = [
            (
                max(
                    len(header),
                    *(
                        len(row[index])
                        for row in rows
                    ),
                )
                if rows
                else len(header)
            )
            for index, header in enumerate(headers)
        ]

        print("\033c", end="")
        print("NetShield ML WIDS - Live Packet Capture")
        print(f"Interface: {self.interface}")
        print(self._separator(widths))

        print(
            "| "
            + " | ".join(
                header.ljust(widths[index])
                for index, header in enumerate(headers)
            )
            + " |"
        )

        print(self._separator(widths))

        for row in rows:
            print(
                "| "
                + " | ".join(
                    value.ljust(widths[index])
                    for index, value in enumerate(row)
                )
                + " |"
            )

        print(self._separator(widths))
        print(
            f"Packets shown: {len(rows)} | CSV logging active"
        )

    @staticmethod
    def _separator(widths: list[int]) -> str:
        return "+-" + "-+-".join("-" * width for width in widths) + "-+"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Live 802.11 packet capture for NetShield ML WIDS"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help=(
            "Wireless interface, for example wlan0. "
            "Monitor mode is enabled automatically."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"CSV log path. Default: {DEFAULT_OUTPUT}",
    )

    parser.add_argument(
        "--no-monitor-setup",
        action="store_true",
        help=(
            "Skip monitor-mode setup when the interface "
            "is already in monitor mode."
        ),
    )

    return parser.parse_args()

def main() -> int:
    args = _parse_args()
    monitor_interface = args.interface
    monitor_mode_created = False

    try:
        conf.verb = 0

        if not args.no_monitor_setup:
            monitor_interface = enable_monitor_mode(args.interface)
            monitor_mode_created = True

        monitor = LivePacketMonitor(
            interface=monitor_interface,
            output_path=args.output,
        )
        signal.signal(signal.SIGINT, monitor.request_stop)
        signal.signal(signal.SIGTERM, monitor.request_stop)
        monitor.start()
    except PermissionError:
        error_message = (
            "Permission denied. Run with sudo/root privileges."
        )
        print(error_message, file=sys.stderr)
        write_capture_error_status(
            args.output,
            monitor_interface,
            error_message,
        )
        return 1

    except RuntimeError as exc:
        error_message = f"Monitor-mode error: {exc}"
        print(error_message, file=sys.stderr)
        write_capture_error_status(
            args.output,
            monitor_interface,
            error_message,
        )
        return 1

    except OSError as exc:
        error_message = f"Interface error: {exc}"
        print(error_message, file=sys.stderr)
        write_capture_error_status(
            args.output,
            monitor_interface,
            error_message,
        )
        return 1

    except Exception as exc:
        error_message = f"Unexpected error: {exc}"
        print(error_message, file=sys.stderr)
        write_capture_error_status(
            args.output,
            monitor_interface,
            error_message,
        )
        return 1
    finally:
        if monitor_mode_created:
            print(
                f"Restoring {monitor_interface} to managed mode..."
            )
            restore_managed_mode(monitor_interface)

    print("\nPacket capture stopped. CSV log saved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
