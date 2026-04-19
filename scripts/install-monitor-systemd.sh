#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_SRC="$ROOT_DIR/deploy/systemd/portaudit-monitor.service"
TIMER_SRC="$ROOT_DIR/deploy/systemd/portaudit-monitor.timer"
SERVICE_DST="/etc/systemd/system/portaudit-monitor.service"
TIMER_DST="/etc/systemd/system/portaudit-monitor.timer"

if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] Run as root"
    exit 1
fi

install -m 0644 "$SERVICE_SRC" "$SERVICE_DST"
install -m 0644 "$TIMER_SRC" "$TIMER_DST"

systemctl daemon-reload
systemctl enable --now portaudit-monitor.timer

echo "[INFO] Systemd timer installed and started"
systemctl list-timers portaudit-monitor.timer --no-pager
