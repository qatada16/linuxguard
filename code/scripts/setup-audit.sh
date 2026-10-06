#!/bin/sh
# Install telemetry on the designated project VM. Run there with sudo sh.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(id -u)" -ne 0 ]; then
    echo 'Run this script on the VM using sudo sh setup-audit.sh.' >&2
    exit 1
fi
if [ "$(hostname)" != linuxguard-target ] || [ "$(uname -m)" != x86_64 ]; then
    echo 'This setup is only for the x86_64 linuxguard-target lab VM.' >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rules_source=$script_dir/linuxguard.rules
test -r "$rules_source" || { echo 'Place linuxguard.rules beside this script.' >&2; exit 1; }
for command in auditctl augenrules usermod install getent systemctl; do
    command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
getent passwd bonzo >/dev/null
getent group adm >/dev/null
systemctl is-active --quiet auditd
status=$(auditctl -s)
printf '%s\n' "$status"
if [ "$(printf '%s\n' "$status" | awk '$1 == "enabled" {print $2}')" != 1 ]; then
    echo 'Auditing must be enabled and unlocked before setup. No files changed.' >&2
    exit 1
fi
active_rules=$(auditctl -l)
printf '%s\n' "$active_rules"
if printf '%s\n' "$active_rules" | grep -Eq 'never,task|task,never'; then
    echo 'An existing never,task rule disables syscall auditing. Resolve it first.' >&2
    exit 1
fi
log_path=$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2}' /etc/audit/auditd.conf)
if [ "${log_path:-/var/log/audit/audit.log}" != /var/log/audit/audit.log ]; then
    echo 'Custom audit log path detected; review configuration before setup.' >&2
    exit 1
fi
test -f /var/log/audit/audit.log
while read -r directive path remainder; do
    if [ "$directive" = -w ] && [ ! -e "$path" ]; then
        echo "Watch path does not exist: $path. No files changed." >&2
        exit 1
    fi
done < "$rules_source"

umask 077
backup=$(mktemp -d /root/linuxguard-audit-backup.XXXXXX)
cp -a /etc/audit "$backup/audit"
printf '%s\n' "$active_rules" > "$backup/active.rules"
printf '%s\n' "$status" > "$backup/status.txt"
id bonzo > "$backup/collector-user.txt"
printf 'Original audit configuration backed up to %s\n' "$backup"
trap 'result=$?; if [ "$result" -ne 0 ]; then echo "Setup stopped; inspect the error above. Original configuration is in $backup." >&2; fi' 0

install -o root -g root -m 0600 "$rules_source" /etc/audit/rules.d/70-linuxguard.rules
if [ -d /root/.ssh ]; then
    echo '-w /root/.ssh -p wa -k lg_ssh' >> /etc/audit/rules.d/70-linuxguard.rules
fi
augenrules --load
loaded_rules=$(auditctl -l)
for key in lg_exec lg_mode lg_identity lg_priv lg_ssh lg_persist lg_shadow_read; do
    if ! printf '%s\n' "$loaded_rules" | grep -qw "$key"; then
        echo "Expected audit key is not loaded: $key" >&2
        exit 1
    fi
done

if grep -Eq '^[[:space:]]*log_group[[:space:]]*=' /etc/audit/auditd.conf; then
    sed -i 's/^[[:space:]]*log_group[[:space:]]*=.*/log_group = adm/' /etc/audit/auditd.conf
else
    printf '\nlog_group = adm\n' >> /etc/audit/auditd.conf
fi
usermod -a -G adm bonzo
chgrp adm /var/log/audit /var/log/audit/audit.log
chmod 0750 /var/log/audit
chmod g+r,o-rwx /var/log/audit/audit.log
auditctl --signal reload
systemctl is-active --quiet auditd
auditctl -s
printf '%s\n' "$loaded_rules"
echo 'LINUXGUARD_AUDIT_SETUP_COMPLETE'
echo 'Reconnect over SSH to pick up adm membership, then verify log access and rule events.'
