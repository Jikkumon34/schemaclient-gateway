#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/scripts/provision_ec2.sh"
  exit 1
fi

APP_USER="${APP_USER:-ubuntu}"
APP_GROUP="${APP_GROUP:-www-data}"
APP_HOME="${APP_HOME:-/home/${APP_USER}/schemaclient-gateway}"
PROJECT_DIR="${APP_HOME}/schemaclienttunnel"
VENV_DIR="${APP_HOME}/.venv"
ENV_FILE="${APP_HOME}/.env"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/7] Installing OS packages"
apt-get update
apt-get install -y python3 python3-venv nginx

echo "[2/7] Preparing folders"
mkdir -p "${APP_HOME}/data"
chown -R "${APP_USER}:${APP_GROUP}" "${APP_HOME}"

echo "[3/7] Setting up virtualenv"
if [[ ! -d "${VENV_DIR}" ]]; then
  sudo -u "${APP_USER}" python3 -m venv "${VENV_DIR}"
fi
sudo -u "${APP_USER}" "${VENV_DIR}/bin/pip" install --upgrade pip
sudo -u "${APP_USER}" "${VENV_DIR}/bin/pip" install -r "${PROJECT_DIR}/requirements.txt"

echo "[4/7] Preparing environment file"
if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${DEPLOY_DIR}/env/gateway.env.example" "${ENV_FILE}"
  chown "${APP_USER}:${APP_GROUP}" "${ENV_FILE}"
  echo "Created ${ENV_FILE}. Update DJANGO_SECRET_KEY and domain values before restart."
fi

echo "[5/7] Running Django setup"
sudo -u "${APP_USER}" "${VENV_DIR}/bin/python" "${PROJECT_DIR}/manage.py" migrate --noinput
sudo -u "${APP_USER}" "${VENV_DIR}/bin/python" "${PROJECT_DIR}/manage.py" collectstatic --noinput

echo "[6/7] Installing systemd and nginx configs"
cp "${DEPLOY_DIR}/systemd/schemaclient-gateway.service" /etc/systemd/system/schemaclient-gateway.service
cp "${DEPLOY_DIR}/nginx/schemaclient-gateway.conf" /etc/nginx/sites-available/schemaclient-gateway.conf
ln -sf /etc/nginx/sites-available/schemaclient-gateway.conf /etc/nginx/sites-enabled/schemaclient-gateway.conf

echo "[7/7] Enabling services"
systemctl daemon-reload
systemctl enable --now schemaclient-gateway
nginx -t
systemctl reload nginx

echo "Provisioning complete."
