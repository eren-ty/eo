#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/eo-site-creator}"
SERVICE_NAME="${SERVICE_NAME:-eo-site-creator.service}"
SERVICE_SRC="${APP_DIR}/deploy/${SERVICE_NAME}"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}"

if [[ ! -f "${SERVICE_SRC}" ]]; then
  echo "Missing service file: ${SERVICE_SRC}" >&2
  exit 1
fi

if [[ ! -f "${APP_DIR}/tencent-eo-new.env" ]]; then
  echo "Warning: ${APP_DIR}/tencent-eo-new.env does not exist yet." >&2
fi

if [[ ! -f "${APP_DIR}/dns-providers.env" ]]; then
  echo "Warning: ${APP_DIR}/dns-providers.env does not exist yet." >&2
fi

install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"

echo "Installed ${SERVICE_NAME}"
echo "Start:   systemctl start ${SERVICE_NAME}"
echo "Restart: systemctl restart ${SERVICE_NAME}"
echo "Status:  systemctl status ${SERVICE_NAME} --no-pager"
echo "Logs:    journalctl -u ${SERVICE_NAME} -f"
