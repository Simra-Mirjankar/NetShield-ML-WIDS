"""CSV logger for captured WiFi packet metadata."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from packet_analyzer import PacketAnalysis


CSV_HEADERS = [
    "Timestamp",
    "Timestamp Epoch",
    "Packet Type",
    "Source MAC",
    "Destination MAC",
    "BSSID",
    "SSID",
    "Frame Type",
    "Frame Type ID",
    "Frame Subtype ID",
    "Signal Strength",
    "Channel",
    "Sequence Number",
    "Fragment Number",
    "Retry Flag",
    "Protected Flag",
    "To DS",
    "From DS",
    "Duration",
    "Frame Length",
    "Reason Code",
    "EAPOL Present",
]


class PacketCSVLogger:
    """Append packet analysis rows to a CSV file."""

    def __init__(self, csv_path: str | Path) -> None:
        self.csv_path = Path(csv_path)
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_header()
        self.session_start_row = self._count_data_rows()

    def log_packet(self, analysis: PacketAnalysis) -> None:
        with self.csv_path.open("a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
            writer.writerow(analysis.as_csv_row())

    def _count_data_rows(self) -> int:
        """Return packet rows that existed before this session."""
        if not self.csv_path.exists():
            return 0

        with self.csv_path.open(
            "r",
            newline="",
            encoding="utf-8",
        ) as csv_file:
            return sum(1 for _ in csv.DictReader(csv_file))


    def _ensure_header(self) -> None:
        if self.csv_path.exists() and self.csv_path.stat().st_size > 0:
            with self.csv_path.open("r", newline="", encoding="utf-8") as csv_file:
                reader = csv.reader(csv_file)
                existing_header = next(reader, [])

            if existing_header == CSV_HEADERS:
                return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            legacy_path = self.csv_path.with_name(
                f"{self.csv_path.stem}_legacy_{timestamp}{self.csv_path.suffix}"
            )
            self.csv_path.rename(legacy_path)

        with self.csv_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
            writer.writeheader()
