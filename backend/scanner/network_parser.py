"""Helpers for extracting WiFi network details from 802.11 beacon/probe frames."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp


CHANNEL_FREQUENCIES_2GHZ = {
    1: 2412,
    2: 2417,
    3: 2422,
    4: 2427,
    5: 2432,
    6: 2437,
    7: 2442,
    8: 2447,
    9: 2452,
    10: 2457,
    11: 2462,
    12: 2467,
    13: 2472,
    14: 2484,
}


@dataclass(frozen=True)
class NetworkDetails:
    """Normalized access point details discovered from a management frame."""

    ssid: str
    bssid: str
    channel: int | None
    frequency: str
    signal_dbm: int | None
    encryption: str

    def as_dict(self) -> dict[str, str | int | None]:
        return {
            "SSID": self.ssid,
            "BSSID": self.bssid,
            "Channel": self.channel,
            "Frequency": self.frequency,
            "Signal": self.signal_dbm,
            "Encryption": self.encryption,
        }


def _decode_ssid(raw_ssid: bytes | str | None) -> str:
    if raw_ssid is None:
        return "<hidden>"
    if isinstance(raw_ssid, bytes):
        if not raw_ssid:
            return "<hidden>"
        return raw_ssid.decode("utf-8", errors="replace")
    return raw_ssid or "<hidden>"


def _iter_dot11_elements(packet: Any):
    element = packet.getlayer(Dot11Elt)
    while element is not None:
        yield element
        element = element.payload.getlayer(Dot11Elt)


def _extract_channel(packet: Any) -> int | None:
    for element in _iter_dot11_elements(packet):
        if element.ID == 3 and element.info:
            return int(element.info[0])
    return None


def _channel_to_frequency(channel: int | None) -> str:
    if channel is None:
        return "Unknown"
    if channel in CHANNEL_FREQUENCIES_2GHZ:
        return f"{CHANNEL_FREQUENCIES_2GHZ[channel]} MHz"
    if 32 <= channel <= 177:
        return f"{5000 + (channel * 5)} MHz"
    return "Unknown"


def _has_rsn_ie(packet: Any) -> bool:
    return any(element.ID == 48 for element in _iter_dot11_elements(packet))


def _has_wpa_vendor_ie(packet: Any) -> bool:
    for element in _iter_dot11_elements(packet):
        if element.ID == 221 and bytes(element.info).startswith(b"\x00\x50\xf2\x01\x01\x00"):
            return True
    return False


def _detect_wpa3(packet: Any) -> bool:
    """Best-effort WPA3 detection from RSN AKM suites.

    AKM suite types 8 and 9 indicate SAE-based WPA3 Personal modes.
    Type 18 indicates WPA3 Enterprise 192-bit mode.
    """

    for element in _iter_dot11_elements(packet):
        if element.ID != 48:
            continue

        rsn = bytes(element.info)
        if len(rsn) < 14:
            continue

        offset = 2
        offset += 4
        if len(rsn) < offset + 2:
            continue

        pairwise_count = int.from_bytes(rsn[offset : offset + 2], "little")
        offset += 2 + (pairwise_count * 4)
        if len(rsn) < offset + 2:
            continue

        akm_count = int.from_bytes(rsn[offset : offset + 2], "little")
        offset += 2
        akm_suites = rsn[offset : offset + (akm_count * 4)]

        for index in range(0, len(akm_suites), 4):
            suite = akm_suites[index : index + 4]
            if len(suite) == 4 and suite[:3] == b"\x00\x0f\xac" and suite[3] in {8, 9, 18}:
                return True

    return False


def _detect_encryption(packet: Any) -> str:
    capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
    privacy_enabled = "privacy" in capability.lower()

    has_rsn = _has_rsn_ie(packet)
    has_wpa = _has_wpa_vendor_ie(packet)

    if _detect_wpa3(packet):
        return "WPA3"
    if has_rsn:
        return "WPA2"
    if has_wpa:
        return "WPA"
    if privacy_enabled:
        return "WEP"
    return "Open"


def extract_network_details(packet: Any) -> NetworkDetails | None:
    """Extract AP metadata from a Scapy packet.

    Returns None for packets that are not beacon or probe-response frames.
    """

    if not packet.haslayer(Dot11) or not (
        packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)
    ):
        return None

    bssid = packet[Dot11].addr2
    if not bssid:
        return None

    ssid_element = packet.getlayer(Dot11Elt)
    ssid = _decode_ssid(getattr(ssid_element, "info", None))
    channel = _extract_channel(packet)
    signal_dbm = getattr(packet, "dBm_AntSignal", None)

    return NetworkDetails(
        ssid=ssid,
        bssid=bssid.upper(),
        channel=channel,
        frequency=_channel_to_frequency(channel),
        signal_dbm=int(signal_dbm) if signal_dbm is not None else None,
        encryption=_detect_encryption(packet),
    )
