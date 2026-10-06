#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVICE_NAME="netshield-ml-scanner.service"
CAPTURE_SERVICE_NAME="netshield-ml-capture.service"
INTERFACE="${1:-wlan0}"

INSTALL_DIR="/opt/netshield-ml-wids-scanner"
APP_DIR="${INSTALL_DIR}/app"
VENV_DIR="${INSTALL_DIR}/venv"

SCANNER_SOURCE="${PROJECT_ROOT}/backend/scanner"

OUTPUT_DIR="${PROJECT_ROOT}/backend/data/scan_results"
OUTPUT_CSV="${OUTPUT_DIR}/wifi_scan_results.csv"

CURRENT_USER="${SUDO_USER:-$USER}"
SYSTEMCTL="$(command -v systemctl)"

echo "Installing NetShield ML WiFi scanner..."
echo "Interface: ${INTERFACE}"
echo "Project:   ${PROJECT_ROOT}"

mkdir -p "${OUTPUT_DIR}"

sudo mkdir -p "${APP_DIR}"

sudo cp \
    "${SCANNER_SOURCE}/wifi_scanner.py" \
    "${SCANNER_SOURCE}/network_parser.py" \
    "${SCANNER_SOURCE}/csv_logger.py" \
    "${APP_DIR}/"

if [ ! -x "${VENV_DIR}/bin/python" ]; then
    sudo python3 -m venv "${VENV_DIR}"
fi

sudo "${VENV_DIR}/bin/python" -m pip install --upgrade pip
sudo "${VENV_DIR}/bin/python" -m pip install "scapy==2.7.0"

sudo tee "/etc/systemd/system/${SERVICE_NAME}" >/dev/null <<SERVICE
[Unit]
Description=NetShield ML WiFi Scanner
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}

Environment="PATH=${VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Prevent scanner from starting while packet capture is active.
ExecStartPre=/bin/sh -c '! ${SYSTEMCTL} is-active --quiet ${CAPTURE_SERVICE_NAME}'

ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/wifi_scanner.py --interface ${INTERFACE} --output ${OUTPUT_CSV}

KillSignal=SIGTERM
TimeoutStopSec=45
Restart=no

[Install]
WantedBy=multi-user.target
SERVICE

sudo tee /etc/sudoers.d/netshield-ml-scanner >/dev/null <<SUDOERS
${CURRENT_USER} ALL=(root) NOPASSWD: ${SYSTEMCTL} start ${SERVICE_NAME}, ${SYSTEMCTL} stop ${SERVICE_NAME}
SUDOERS

sudo chmod 440 /etc/sudoers.d/netshield-ml-scanner

sudo visudo -cf /etc/sudoers.d/netshield-ml-scanner

sudo systemctl daemon-reload

echo
echo "Scanner service installed successfully."
echo "Service was NOT started."
