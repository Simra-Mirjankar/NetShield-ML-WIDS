import json
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

from scanner.adapter_manager import read_adapter_status
from scanner.network_reader import read_networks
from scanner.scanner_service import (
    read_scanner_status,
    start_scanner,
    stop_scanner,
)
from packet_capture.packet_reader import read_packet_feed
from packet_capture.capture_service import (
    read_capture_status,
    start_capture,
    stop_capture,
)
from ml.inference_service import create_v3_inference_service
from data.incident_store import get_incidents


app = Flask(__name__)
CORS(app)

ml_service = create_v3_inference_service()

ML_LIVE_STATUS_JSON = (
    Path(__file__).resolve().parent
    / "data"
    / "packet_logs"
    / "ml_live_status.json"
)


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "message": "NetShield backend is running",
        }
    )


@app.get("/api/interfaces")
def interfaces():
    return jsonify(read_adapter_status())


from ml.ap_assessment import assess_ap_security


@app.get("/api/networks")
def networks():
    network_rows = read_networks()

    return jsonify(
        {
            "count": len(network_rows),
            "networks": network_rows,
        }
    )


@app.route("/api/networks/assess", methods=["GET", "POST"])
def assess_network():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        bssid = data.get("bssid") or request.args.get("bssid")
    else:
        bssid = request.args.get("bssid")

    if not bssid:
        return (
            jsonify(
                {"error": "Query parameter or JSON field 'bssid' is required."}
            ),
            400,
        )

    result = assess_ap_security(bssid, inference_service=ml_service)
    return jsonify(result)



@app.get("/api/scanner/status")
def scanner_status():
    return jsonify(read_scanner_status())


@app.post("/api/scanner/start")
def scanner_start():
    data = request.get_json(silent=True) or {}

    response, status_code = start_scanner(
        data.get("interface")
    )

    return jsonify(response), status_code


@app.post("/api/scanner/stop")
def scanner_stop():
    response, status_code = stop_scanner()

    return jsonify(response), status_code



@app.get("/api/packets")
def packets():
    limit = request.args.get(
        "limit",
        default=50,
        type=int,
    )

    return jsonify(
        read_packet_feed(limit=limit)
    )


@app.get("/api/capture/status")
def capture_status():
    return jsonify(read_capture_status())


@app.post("/api/capture/start")
def capture_start():
    data = request.get_json(silent=True) or {}

    response, status_code = start_capture(
        data.get("interface")
    )

    return jsonify(response), status_code


@app.post("/api/capture/stop")
def capture_stop():
    response, status_code = stop_capture()

    return jsonify(response), status_code


@app.get("/api/ml/status")
def ml_status():
    return jsonify(
        {
            "status": "ok",
            "model": "random_forest_awid3_v3_expanded",
            "feature_count": 31,
        }
    )


@app.post("/api/ml/analyze-window")
def ml_analyze_window():
    data = request.get_json(silent=True) or {}

    if (
        not isinstance(data, dict)
        or "packets" not in data
        or not isinstance(data["packets"], list)
    ):
        return (
            jsonify(
                {
                    "error": "Request body must be a JSON object with a 'packets' list."
                }
            ),
            400,
        )

    try:
        result = ml_service.analyze_window(data["packets"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


@app.get("/api/ml/live-status")
def ml_live_status():
    if not ML_LIVE_STATUS_JSON.exists():
        return jsonify({"status": "no_inference"})

    try:
        payload = json.loads(
            ML_LIVE_STATUS_JSON.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return jsonify({"status": "no_inference"})

    if not isinstance(payload, dict):
        return jsonify({"status": "no_inference"})

    return jsonify(payload)


@app.get("/api/incidents")
def incidents():
    incident_rows = get_incidents()

    return jsonify(
        {
            "count": len(incident_rows),
            "incidents": incident_rows,
        }
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
    )
