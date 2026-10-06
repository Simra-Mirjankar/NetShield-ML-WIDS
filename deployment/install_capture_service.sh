#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVICE_NAME="netshield-ml-capture.service"
SCANNER_SERVICE_NAME="netshield-ml-scanner.service"
INTERFACE="${1:-wlan0}"

INSTALL_ROOT="/opt/netshield-ml-capture"
APP_DIR="${INSTALL_ROOT}/app"
VENV_DIR="${INSTALL_ROOT}/venv"

SOURCE_DIR="${PROJECT_ROOT}/backend/packet_capture"

OUTPUT_DIR="${PROJECT_ROOT}/backend/data/packet_logs"
OUTPUT_FILE="${OUTPUT_DIR}/wifi_packets.csv"

CURRENT_USER="${SUDO_USER:-$USER}"
SYSTEMCTL="$(command -v systemctl)"

required_files=(
    "${SOURCE_DIR}/packet_sniffer.py"
    "${SOURCE_DIR}/packet_analyzer.py"
    "${SOURCE_DIR}/packet_logger.py"
)

for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
        echo "Required file missing: ${file}" >&2
        exit 1
    fi
done

echo "Installing NetShield ML packet capture..."
echo "Interface: ${INTERFACE}"
echo "Project:   ${PROJECT_ROOT}"

mkdir -p "${OUTPUT_DIR}"

sudo install -d -m 0755 "${APP_DIR}"

sudo install -m 0644 \
    "${SOURCE_DIR}/packet_sniffer.py" \
    "${SOURCE_DIR}/packet_analyzer.py" \
    "${SOURCE_DIR}/packet_logger.py" \
    "${APP_DIR}/"

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    sudo python3 -m venv "${VENV_DIR}"
fi

sudo "${VENV_DIR}/bin/python" -m pip install --upgrade pip
sudo "${VENV_DIR}/bin/python" -m pip install "scapy==2.7.0"

sudo tee "/etc/systemd/system/${SERVICE_NAME}" >/dev/null <<SERVICE
[Unit]
Description=NetShield ML Live WiFi Packet Capture
After=network.target
ConditionPathExists=${APP_DIR}/packet_sniffer.py

[Service]
Type=simple
WorkingDirectory=${APP_DIR}

Environment=PYTHONUNBUFFERED=1
Environment="PATH=${VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ExecStartPre=/bin/sh -c '! ${SYSTEMCTL} is-active --quiet ${SCANNER_SERVICE_NAME}'

ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/packet_sniffer.py --interface ${INTERFACE} --output ${OUTPUT_FILE}

KillSignal=SIGTERM
TimeoutStopSec=45
Restart=no

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

sudo tee /etc/sudoers.d/netshield-ml-capture >/dev/null <<SUDOERS
${CURRENT_USER} ALL=(root) NOPASSWD: ${SYSTEMCTL} start ${SERVICE_NAME}, ${SYSTEMCTL} stop ${SERVICE_NAME}
SUDOERS

sudo chmod 440 /etc/sudoers.d/netshield-ml-capture

sudo visudo -cf /etc/sudoers.d/netshield-ml-capture

sudo systemctl daemon-reload

echo
echo "Packet-capture service installed successfully."
echo "Service was NOT started."
