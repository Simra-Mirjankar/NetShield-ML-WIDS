"""802.11 packet parsing for NetShield ML WIDS.

This module extracts packet metadata only.
It does NOT decide whether traffic is malicious.
Attack detection will be handled by the ML pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import time
from typing import Any

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, Dot11Elt
from scapy.layers.eap import EAPOL


@dataclass(frozen=True)
class PacketAnalysis:
    """Normalized metadata extracted from one WiFi frame."""

    timestamp: str
    timestamp_epoch: float
    packet_type: str
    source_mac: str
    destination_mac: str
    bssid: str
    ssid: str | None
    frame_type: str
    frame_type_id: int | None
    frame_subtype_id: int | None
    signal_strength: int | None
    channel: int | None
    sequence_number: int | None
    fragment_number: int | None
    retry_flag: int
    protected_flag: int
    to_ds: int
    from_ds: int
    duration: int | None
    frame_length: int | None
    reason_code: int | None
    eapol_present: int

    def as_csv_row(self) -> dict[str, str | float | int | None]:
        return {
            "Timestamp": self.timestamp,
            "Timestamp Epoch": self.timestamp_epoch,
            "Packet Type": self.packet_type,
            "Source MAC": self.source_mac,
            "Destination MAC": self.destination_mac,
            "BSSID": self.bssid,
            "SSID": self.ssid,
            "Frame Type": self.frame_type,
            "Frame Type ID": self.frame_type_id,
            "Frame Subtype ID": self.frame_subtype_id,
            "Signal Strength": self.signal_strength,
            "Channel": self.channel,
            "Sequence Number": self.sequence_number,
            "Fragment Number": self.fragment_number,
            "Retry Flag": self.retry_flag,
            "Protected Flag": self.protected_flag,
            "To DS": self.to_ds,
            "From DS": self.from_ds,
            "Duration": self.duration,
            "Frame Length": self.frame_length,
            "Reason Code": self.reason_code,
            "EAPOL Present": self.eapol_present,
        }


class PacketAnalyzer:
    """Parse useful 802.11 frames without attack classification."""

    def analyze_packet(
        self,
        packet: Any,
        capture_channel: int | None = None,
    ) -> PacketAnalysis | None:

        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]

        packet_type = self._classify_packet(dot11)

        if packet_type is None:
            return None

        source_mac = self._normalize_mac(
            dot11.addr2
        )

        destination_mac = self._normalize_mac(
            dot11.addr1
        )

        bssid = self._extract_bssid(dot11)

        frame_type = self._frame_type_name(
            dot11.type
        )

        signal_strength = getattr(
            packet,
            "dBm_AntSignal",
            None,
        )

        now = time.time()
        sequence_control = self._safe_int(getattr(dot11, "SC", None))
        sequence_number = None
        fragment_number = None

        if sequence_control is not None:
            fragment_number = sequence_control & 0xF
            sequence_number = (sequence_control >> 4) & 0xFFF

        fcfield = self._safe_int(getattr(dot11, "FCfield", 0)) or 0

        return PacketAnalysis(
            timestamp=datetime.fromtimestamp(now).strftime("%H:%M:%S"),
            timestamp_epoch=now,
            packet_type=packet_type,
            source_mac=source_mac,
            destination_mac=destination_mac,
            bssid=bssid,
            ssid=self._extract_ssid(packet),
            frame_type=frame_type,
            frame_type_id=self._safe_int(getattr(dot11, "type", None)),
            frame_subtype_id=self._safe_int(getattr(dot11, "subtype", None)),
            signal_strength=(
                int(signal_strength)
                if signal_strength is not None
                else None
            ),
            channel=self._safe_int(capture_channel),
            sequence_number=sequence_number,
            fragment_number=fragment_number,
            retry_flag=1 if fcfield & 0x08 else 0,
            protected_flag=1 if fcfield & 0x40 else 0,
            to_ds=1 if fcfield & 0x01 else 0,
            from_ds=1 if fcfield & 0x02 else 0,
            duration=self._safe_int(getattr(dot11, "ID", None)),
            frame_length=self._safe_packet_length(packet),
            reason_code=self._extract_reason_code(packet),
            eapol_present=1 if packet.haslayer(EAPOL) else 0,
        )

    @staticmethod
    def _classify_packet(
        dot11: Dot11,
    ) -> str | None:

        # Management frames
        if dot11.type == 0:
            subtype_map = {
                0: "Association Request",
                1: "Association Response",
                2: "Reassociation Request",
                3: "Reassociation Response",
                4: "Probe Request",
                5: "Probe Response",
                8: "Beacon",
                10: "Disassociation",
                11: "Authentication",
                12: "Deauthentication",
                13: "Action",
            }

            return subtype_map.get(
                dot11.subtype,
                "Management",
            )

        # Control frames
        if dot11.type == 1:
            return "Control"

        # Data frames
        if dot11.type == 2:
            return "Data"

        return None

    def _extract_bssid(
        self,
        dot11: Dot11,
    ) -> str:

        if dot11.type == 0:
            if dot11.subtype == 4:
                return "Broadcast"

            return self._normalize_mac(
                dot11.addr3 or dot11.addr2
            )

        if dot11.type == 2:
            return self._normalize_mac(
                dot11.addr3
            )

        return "Unknown"

    @staticmethod
    def _normalize_mac(
        mac_address: str | None,
    ) -> str:

        if not mac_address:
            return "Unknown"

        if mac_address.lower() == (
            "ff:ff:ff:ff:ff:ff"
        ):
            return "Broadcast"

        return mac_address.upper()

    @staticmethod
    def _extract_ssid(packet: Any) -> str | None:
        element = packet.getlayer(Dot11Elt)

        while element is not None:
            if getattr(element, "ID", None) == 0:
                ssid_bytes = getattr(element, "info", b"")

                if isinstance(ssid_bytes, bytes):
                    return ssid_bytes.decode("utf-8", errors="replace")

                return str(ssid_bytes)

            element = element.payload.getlayer(Dot11Elt)

        return None

    @staticmethod
    def _extract_reason_code(packet: Any) -> int | None:
        for layer in (Dot11Deauth, Dot11Disas):
            if packet.haslayer(layer):
                reason_code = getattr(packet[layer], "reason", None)
                return PacketAnalyzer._safe_int(reason_code)

        return None

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_packet_length(packet: Any) -> int | None:
        try:
            return len(packet)
        except TypeError:
            return None

    @staticmethod
    def _frame_type_name(
        frame_type: int,
    ) -> str:

        return {
            0: "Management",
            1: "Control",
            2: "Data",
            3: "Extension",
        }.get(
            frame_type,
            "Unknown",
        )
