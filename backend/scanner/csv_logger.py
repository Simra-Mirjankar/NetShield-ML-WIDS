"""CSV logging for WiFi scan results."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Mapping


CSV_HEADERS = ["SSID", "BSSID", "Channel", "Frequency", "Signal", "Encryption"]


def save_to_csv(
    networks: Mapping[str, Mapping[str, str | int | None]],
    csv_path: str | Path = "wifi_scan_results.csv",
) -> None:
    """Save the current scanner-session snapshot, unique by BSSID."""
    output_path = Path(csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    snapshot_networks = {}

    for network in networks.values():
        bssid = str(network.get("BSSID") or "").strip().upper()
        if not bssid:
            continue

        snapshot_networks[bssid] = {
            header: "" if network.get(header) is None else str(network.get(header, ""))
            for header in CSV_HEADERS
        }

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for network in sorted(
            snapshot_networks.values(),
            key=lambda item: (item.get("SSID", ""), item.get("BSSID", "")),
        ):
            writer.writerow({header: network.get(header, "") for header in CSV_HEADERS})
