#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-./lab-baseline}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "capture_baseline.sh must be run as root" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"
cp /var/log/audit/audit.log "${OUTPUT_DIR}/audit.log"
cp /var/log/auth.log "${OUTPUT_DIR}/auth.log"
cp /etc/passwd "${OUTPUT_DIR}/passwd"
echo "[]" > "${OUTPUT_DIR}/labels.json"
chmod -R go-rwx "${OUTPUT_DIR}"
echo "Baseline capture written to ${OUTPUT_DIR}. Only capture periods of known benign activity."
