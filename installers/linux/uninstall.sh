#!/usr/bin/env bash
# VenueDesk Agent Linux Uninstaller
# Cleanly stops and removes VenueDesk Agent service and components.
# Usage: sudo ./uninstall.sh [--purge]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This uninstaller must be executed as root." >&2
   exit 1
fi

PURGE=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --purge)
      PURGE=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

echo ">>> Stopping and disabling venuedesk-agent systemd service..."
if systemctl is-active --quiet venuedesk-agent.service 2>/dev/null; then
    systemctl stop venuedesk-agent.service || true
fi

if systemctl is-enabled --quiet venuedesk-agent.service 2>/dev/null; then
    systemctl disable venuedesk-agent.service || true
fi

echo ">>> Removing systemd unit and binary links..."
rm -f /etc/systemd/system/venuedesk-agent.service
rm -f /usr/local/bin/venuedesk-evidence-helper
systemctl daemon-reload

echo ">>> Removing application files from /opt/venuedesk-agent..."
rm -rf /opt/venuedesk-agent

if [[ "${PURGE}" == "true" ]]; then
    echo ">>> Purging state, configuration, and log directories..."
    rm -rf /etc/venuedesk
    rm -rf /var/lib/venuedesk-agent
    rm -rf /var/log/venuedesk-agent
    if id -u venuedesk &>/dev/null; then
        userdel venuedesk || true
    fi
    echo ">>> Full purge complete. All device keys, config, and state deleted."
else
    echo ">>> Preserving /etc/venuedesk and /var/lib/venuedesk-agent (pass --purge to remove)."
fi

echo ">>> VenueDesk Agent successfully uninstalled."
