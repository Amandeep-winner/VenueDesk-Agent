#!/usr/bin/env bash
# VenueDesk Agent Linux Production Installer
# Usage: sudo ./install.sh [--server https://control.venue.internal] [--token PAIR-...]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This installer must be executed as root." >&2
   exit 1
fi

SERVER_URL="https://127.0.0.1:5001"
PAIRING_TOKEN=""
CONFIG_DIR="/etc/venuedesk"
STATE_DIR="/var/lib/venuedesk-agent"
LOG_DIR="/var/log/venuedesk-agent"
INSTALL_DIR="/opt/venuedesk-agent"

while [[ $# -gt 0 ]]; do
  case $1 in
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --token)
      PAIRING_TOKEN="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

echo ">>> Creating dedicated 'venuedesk' system user..."
if ! id -u venuedesk &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir "${STATE_DIR}" venuedesk
fi

echo ">>> Setting up secure state, log, and configuration directories..."
mkdir -p "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" "${INSTALL_DIR}"
chown -R venuedesk:venuedesk "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}"
chmod 0750 "${CONFIG_DIR}"
chmod 0700 "${STATE_DIR}"
chmod 0750 "${LOG_DIR}"

echo ">>> Installing privileged evidence cache helper..."
cp "$(dirname "$0")/venuedesk-evidence-helper" /usr/local/bin/venuedesk-evidence-helper
chmod 0755 /usr/local/bin/venuedesk-evidence-helper
/usr/local/bin/venuedesk-evidence-helper

echo ">>> Setting up Python virtual environment..."
python3 -m venv "${INSTALL_DIR}"
"${INSTALL_DIR}/bin/pip" install --upgrade pip
"${INSTALL_DIR}/bin/pip" install -e "$(dirname "$0")/../../venuedesk-agent"

echo ">>> Generating /etc/venuedesk/config.toml..."
cat <<EOF > "${CONFIG_DIR}/config.toml"
server_url = "${SERVER_URL}"
deployment_salt = "venuedesk-default-salt-32-chars-long!"
heartbeat_seconds = 60
telemetry_seconds = 60
inventory_seconds = 21600
jobs_poll_seconds = 60
key_store = "file"
state_dir = "${STATE_DIR}"
allow_insecure_dev = false
log_level = "INFO"
approved_services = []
diagnostic_allowlist = ["127.0.0.1", "localhost"]
EOF
chown venuedesk:venuedesk "${CONFIG_DIR}/config.toml"
chmod 0640 "${CONFIG_DIR}/config.toml"

if [[ -n "${PAIRING_TOKEN}" ]]; then
    echo ">>> Enrolling endpoint with provided pairing token..."
    sudo -u venuedesk "${INSTALL_DIR}/bin/python" -m agent.main enroll \
        --config "${CONFIG_DIR}/config.toml" \
        --server "${SERVER_URL}" \
        --token "${PAIRING_TOKEN}"
fi

echo ">>> Installing and starting systemd service..."
cp "$(dirname "$0")/venuedesk-agent.service" /etc/systemd/system/venuedesk-agent.service
systemctl daemon-reload
systemctl enable venuedesk-agent.service
systemctl restart venuedesk-agent.service

echo ">>> VenueDesk Agent installation complete and service active."
systemctl status venuedesk-agent.service --no-pager
