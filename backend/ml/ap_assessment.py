"""ML Security Assessment for a selected WiFi network (BSSID).

This module connects real 802.11 packet observations for a specific BSSID
to the frozen AWID3 v3 31-feature Random Forest inference service.

It preserves strict feature integrity:
- If sufficient packet data exists, it extracts the 31-feature V3 vector
  and runs the frozen Random Forest model.
- If insufficient packet data exists, it cleanly reports that ML assessment
  is unavailable without fabricating features or assigning arbitrary predictions.
"""

from __future__ import annotations

import csv
import datetime
from pathlib import Path
from typing import Any

from ml.inference_service import V3InferenceService, create_v3_inference_service

try:
    from data.incident_store import create_incident
except ImportError:
    from backend.data.incident_store import create_incident


PACKET_LOG_CSV = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "packet_logs"
    / "wifi_packets.csv"
)

MINIMUM_WINDOW_PACKETS = 5
DEFAULT_WINDOW_SECONDS = 5.0


def _load_packets_for_bssid(
    bssid: str,
    log_path: Path = PACKET_LOG_CSV,
) -> list[dict[str, Any]]:
    """Read packets matching target BSSID from packet log CSV."""

    if not log_path.exists():
        return []

    target = bssid.strip().upper()
    matching_packets: list[dict[str, Any]] = []

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                pkt_bssid = (row.get("BSSID") or "").strip().upper()
                src_mac = (row.get("Source MAC") or "").strip().upper()
                dst_mac = (row.get("Destination MAC") or "").strip().upper()

                if target in (pkt_bssid, src_mac, dst_mac):
                    raw_epoch = row.get("Timestamp Epoch")
                    if not raw_epoch:
                        continue
                    try:
                        epoch = float(raw_epoch)
                    except ValueError:
                        continue

                    retry_flag = row.get("Retry Flag")
                    try:
                        retry_val = int(retry_flag) if retry_flag is not None and retry_flag != "" else 0
                    except ValueError:
                        retry_val = 0

                    matching_packets.append(
                        {
                            "timestamp_epoch": epoch,
                            "packet_type": row.get("Packet Type") or "Unknown",
                            "source_mac": row.get("Source MAC") or "Unknown",
                            "destination_mac": row.get("Destination MAC") or "Unknown",
                            "bssid": row.get("BSSID") or "Unknown",
                            "frame_type": row.get("Frame Type") or "Unknown",
                            "retry_flag": retry_val,
                        }
                    )
    except OSError:
        return []

    return sorted(matching_packets, key=lambda p: float(p["timestamp_epoch"]))


def _classify_attack_category(result: dict[str, Any], window_packets: list[dict[str, Any]]) -> str:
    """Classify attack category based on window packet dynamics when prediction == 1."""
    deauth_count = sum(1 for p in window_packets if p.get("packet_type") == "Deauthentication")
    disassoc_count = sum(1 for p in window_packets if p.get("packet_type") == "Disassociation")
    assoc_count = sum(1 for p in window_packets if p.get("packet_type") in ("Association Request", "Reassociation Request"))

    if deauth_count > 0 and deauth_count >= disassoc_count:
        return "Deauthentication"
    if disassoc_count > 0:
        return "Disassociation"
    if assoc_count > 0:
        return "(Re)Association"

    return "Rogue AP / Evil Twin"


def assess_ap_security(
    bssid: str,
    inference_service: V3InferenceService | None = None,
    log_path: Path = PACKET_LOG_CSV,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    min_packets: int = MINIMUM_WINDOW_PACKETS,
) -> dict[str, Any]:
    """Perform ML security assessment for a target AP identified by BSSID.

    Returns structured ML assessment dictionary or explicit insufficient-data output.
    """

    target_bssid = bssid.strip().upper()

    if not target_bssid:
        return {
            "ok": False,
            "error": "A valid BSSID is required for ML security assessment.",
        }

    matching_packets = _load_packets_for_bssid(target_bssid, log_path=log_path)

    if not matching_packets:
        return {
            "ok": True,
            "available": False,
            "bssid": target_bssid,
            "reason": "Insufficient compatible packet data for this BSSID.",
            "details": f"No real packet observations recorded for BSSID '{target_bssid}'.",
            "packet_count": 0,
            "feature_count": 31,
            "message": "ML assessment unavailable — insufficient compatible packet data for this BSSID.",
        }

    latest_epoch = max(float(p["timestamp_epoch"]) for p in matching_packets)
    window_packets = [
        p for p in matching_packets
        if float(p["timestamp_epoch"]) >= (latest_epoch - window_seconds)
    ]

    if len(window_packets) < min_packets:
        return {
            "ok": True,
            "available": False,
            "bssid": target_bssid,
            "reason": "Insufficient compatible packet data for this BSSID.",
            "details": (
                f"Only {len(window_packets)} packet(s) observed in the latest {window_seconds}-second window. "
                f"At least {min_packets} packets are required for valid 31-feature V3 ML extraction."
            ),
            "packet_count": len(window_packets),
            "total_ap_packets": len(matching_packets),
            "feature_count": 31,
            "message": "ML assessment unavailable — insufficient compatible packet data for this BSSID.",
        }

    service = inference_service or create_v3_inference_service()

    result = service.analyze_window(window_packets, window_seconds=window_seconds)

    if result.get("feature_count") != 31:
        raise ValueError(
            f"Expected 31 features from V3 inference service, got {result.get('feature_count')}."
        )

    attack_category = None
    if result.get("prediction") == 1:
        attack_category = _classify_attack_category(result, window_packets)
        try:
            create_incident({**result, "label": f"Attack ({attack_category})"})
        except ValueError:
            pass

    return {
        "ok": True,
        "available": True,
        "bssid": target_bssid,
        "prediction": result["prediction"],
        "label": result["label"],
        "attack_probability": result["attack_probability"],
        "normal_probability": result["normal_probability"],
        "attack_category": attack_category,
        "total_packets": result["total_packets"],
        "total_ap_packets": len(matching_packets),
        "window_duration": window_seconds,
        "window_start": result["window_start"],
        "window_end": result["window_end"],
        "feature_count": result["feature_count"],
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": f"ML assessment completed using {result['total_packets']} real packet observations across {result['feature_count']} V3 features.",
    }
