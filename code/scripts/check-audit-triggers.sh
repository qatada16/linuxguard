#!/bin/sh
# Generate inert file events for the remaining audit keys on the project VM.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(id -u)" -ne 0 ]; then
    echo 'Run this on the VM using sudo sh check-audit-triggers.sh.' >&2
    exit 1
fi
if [ "$(hostname)" != linuxguard-target ]; then
    echo 'This check is only for the linuxguard-target lab VM.' >&2
    exit 1
fi
systemctl is-active --quiet auditd
status=$(auditctl -s)
printf '%s\n' "$status"
if [ "$(printf '%s\n' "$status" | awk '$1 == "enabled" {print $2}')" != 1 ] ||
   [ "$(printf '%s\n' "$status" | awk '$1 == "lost" {print $2}')" != 0 ]; then
    echo 'Expected enabled 1 and lost 0; review audit status before generating probes.' >&2
    exit 1
fi
for directory in /etc/sudoers.d /home/bonzo/.ssh /etc/cron.d; do
    test -d "$directory"
done

priv_probe=
ssh_probe=
persist_probe=
cleanup() {
    for probe in "$priv_probe" "$ssh_probe" "$persist_probe"; do
        if [ -n "$probe" ]; then
            rm -f -- "$probe"
        fi
    done
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

printf 'PROBE_START_UTC %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Empty temporary files contain no sudo grants, keys, or cron jobs.
priv_probe=$(mktemp /etc/sudoers.d/.linuxguard-probe.XXXXXX)
printf 'PROBE lg_priv %s\n' "$priv_probe"
ssh_probe=$(mktemp /home/bonzo/.ssh/.linuxguard-probe.XXXXXX)
printf 'PROBE lg_ssh %s\n' "$ssh_probe"
persist_probe=$(mktemp /etc/cron.d/.linuxguard-probe.XXXXXX)
printf 'PROBE lg_persist %s\n' "$persist_probe"
cleanup
printf 'PROBE_END_UTC %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
auditctl -s
echo 'LINUXGUARD_AUDIT_PROBES_COMPLETE'
echo 'Probe files removed. Verify matching SYSCALL and PATH records in the audit log next.'
