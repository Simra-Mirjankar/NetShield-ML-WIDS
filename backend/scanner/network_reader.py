"""Read WiFi scanner results for the NetShield API."""

from __future__ import annotations

import csv
from pathlib import Path

from vendor_lookup.vendor_lookup import (
    load_oui_database,
    lookup_vendor,
)


NETWORK_CSV = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "scan_results"
    / "wifi_scan_results.csv"
)

PACKET_LOG_CSV = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "packet_logs"
    / "wifi_packets.csv"
)

VENDORS = load_oui_database()



def _get_packet_counts_by_bssid() -> dict[str, int]:
    if not PACKET_LOG_CSV.exists():
        return {}

    counts: dict[str, int] = {}
    try:
        with PACKET_LOG_CSV.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                for key in ("BSSID", "Source MAC", "Destination MAC"):
                    mac = (row.get(key) or "").strip().upper()
                    if mac and mac not in ("UNKNOWN", "BROADCAST"):
                        counts[mac] = counts.get(mac, 0) + 1
    except OSError:
        pass

    return counts


def read_networks() -> list[dict]:
    """Return scanned WiFi networks with vendor and ML packet status information."""

    if not NETWORK_CSV.exists():
        return []

    packet_counts = _get_packet_counts_by_bssid()
    networks = []

    with NETWORK_CSV.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        for row in reader:
            ssid = (row.get("SSID") or "").strip()
            bssid = (row.get("BSSID") or "").strip().upper()

            if not ssid and not bssid:
                continue

            pkt_count = packet_counts.get(bssid, 0)
            if pkt_count >= 5:
                status = "READY_FOR_ASSESSMENT"
            elif pkt_count > 0:
                status = "INSUFFICIENT_DATA"
            else:
                status = "NOT_ANALYZED"

            networks.append(
                {
                    "ssid": ssid or "Hidden Network",
                    "bssid": bssid,
                    "channel": (
                        row.get("Channel") or ""
                    ).strip(),
                    "frequency": (
                        row.get("Frequency") or ""
                    ).strip(),
                    "signal": (
                        row.get("Signal") or ""
                    ).strip(),
                    "encryption": (
                        row.get("Encryption")
                        or "Unknown"
                    ).strip(),
                    "vendor": lookup_vendor(
                        bssid,
                        VENDORS,
                    ),
                    "analysis_status": status,
                    "packet_count": pkt_count,
                }
            )

    return networks

