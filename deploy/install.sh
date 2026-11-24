#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR=/opt/linuxguard
CONFIG_DIR=/etc/linuxguard
STATE_DIR=/var/lib/linuxguard
RULES_FILE=/etc/audit/rules.d/50-linuxguard.rules
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
    echo "install.sh must be run as root" >&2
    exit 1
fi

apt-get update -qq
apt-get install -y -qq auditd python3-venv

install -d -m 0755 "${INSTALL_DIR}" "${CONFIG_DIR}"
install -d -m 0700 "${STATE_DIR}" "${STATE_DIR}/models"

python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet "${SOURCE_DIR}[all]"

if [[ ! -f "${CONFIG_DIR}/linuxguard.yaml" ]]; then
    install -m 0600 "${SOURCE_DIR}/config/linuxguard.yaml" "${CONFIG_DIR}/linuxguard.yaml"
fi

install -m 0640 "${SOURCE_DIR}/deploy/audit/linuxguard.rules" "${RULES_FILE}"
while IFS=: read -r _ _ uid _ _ home _; do
    if [[ "${uid}" -ge 1000 && "${uid}" -lt 65534 && -d "${home}" ]]; then
        echo "-w ${home}/.ssh/ -p wa -k lg_ssh_keys" >> "${RULES_FILE}"
    fi
done < /etc/passwd

systemctl enable --now auditd
augenrules --load

install -m 0644 "${SOURCE_DIR}/deploy/systemd/linuxguard.service" /etc/systemd/system/linuxguard.service
systemctl daemon-reload

echo "LinuxGuard installed."
echo "1. Collect a benign baseline, then train it:"
echo "   ${INSTALL_DIR}/venv/bin/linuxguard --config ${CONFIG_DIR}/linuxguard.yaml train --audit-log /var/log/audit/audit.log --auth-log /var/log/auth.log"
echo "2. Start monitoring: systemctl enable --now linuxguard"
echo "   (set detection.mode to 'rules' in ${CONFIG_DIR}/linuxguard.yaml until a baseline has been trained)"
