# Deployment and Lab Setup

LinuxGuard is designed to monitor one Linux host. The recommended setup is an isolated virtual machine.

## 1. Prepare the target virtual machine

| Resource | Minimum | Recommended |
| --- | --- | --- |
| Hypervisor | VirtualBox or KVM/QEMU | KVM/QEMU |
| Guest OS | Ubuntu Server 22.04 LTS or newer | Ubuntu Server 24.04 LTS |
| vCPUs | 2 | 2 |
| Memory | 2 GB | 4 GB |
| Disk | 15 GB | 25 GB |

Use a host-only or NAT network so test scenarios cannot reach other systems. Take a snapshot before running the lab
scenarios so the VM can be restored afterwards.

> The Linux audit subsystem only accepts requests from the initial PID namespace. It therefore does not work inside
> containers or WSL distributions; use a full virtual machine for auditd collection. Authentication monitoring from
> `auth.log` works everywhere.

## 2. Install LinuxGuard

```bash
git clone https://github.com/qatada16/linuxguard.git
cd linuxguard
sudo ./deploy/install.sh
```

The installer:

1. installs `auditd` and `python3-venv`;
2. creates a virtual environment in `/opt/linuxguard/venv` and installs LinuxGuard with the API and dashboard extras;
3. copies [`config/linuxguard.yaml`](../config/linuxguard.yaml) to `/etc/linuxguard/linuxguard.yaml` (mode `0600`);
4. installs the audit rules from [`deploy/audit/linuxguard.rules`](../deploy/audit/linuxguard.rules) as
   `/etc/audit/rules.d/50-linuxguard.rules`, adds a watch for every user's `~/.ssh/` directory and loads them with
   `augenrules --load`;
5. installs the hardened systemd unit [`deploy/systemd/linuxguard.service`](../deploy/systemd/linuxguard.service).

Verify the rules are active:

```bash
sudo auditctl -l | grep lg_
```

## 3. Train the baseline

Use the system normally (logins, administration, development work) for at least a few hours, then train the
Isolation Forest baseline from the collected logs:

```bash
sudo /opt/linuxguard/venv/bin/linuxguard --config /etc/linuxguard/linuxguard.yaml train \
    --audit-log /var/log/audit/audit.log --auth-log /var/log/auth.log
```

Until a baseline exists, set `detection.mode: rules` in the configuration. Retrain periodically so legitimate
changes in behaviour become part of the baseline. The model is written with a SHA-256 digest file and will not be
loaded if either file has been modified.

## 4. Monitor

```bash
sudo systemctl enable --now linuxguard
journalctl -u linuxguard -f
```

or run interactively with `linuxguard monitor`. Alerts are stored in `/var/lib/linuxguard/linuxguard.db`.

## 5. Investigate

```bash
linuxguard --config /etc/linuxguard/linuxguard.yaml alerts --severity high
linuxguard --config /etc/linuxguard/linuxguard.yaml show <alert-id>
linuxguard --config /etc/linuxguard/linuxguard.yaml timeline <alert-id>
linuxguard --config /etc/linuxguard/linuxguard.yaml report <alert-id> --format html --output incident.html
linuxguard --config /etc/linuxguard/linuxguard.yaml dashboard
```

The dashboard and API bind to `127.0.0.1` only. Use an SSH tunnel to reach them from another machine:

```bash
ssh -L 8501:127.0.0.1:8501 user@target-vm
```

Set `LINUXGUARD_API_KEY` before `linuxguard serve` to require an `X-API-Key` header on every API request except
`/health`.

## 6. Optional explanations

* **Local:** install [Ollama](https://ollama.com), pull a model (`ollama pull llama3.2`) and run
  `linuxguard explain <alert-id> --mode local`.
* **Cloud:** only when permitted. Set `LINUXGUARD_CLOUD_API_KEY`, configure `explanation.cloud.endpoint` and
  `model`, and run `linuxguard explain <alert-id> --mode cloud`. The CLI shows the redacted payload and asks for
  consent unless `explanation.cloud.consent_granted` is `true` or `--yes` is given.

## 7. Lab scenarios

The [`lab/`](../lab) directory contains scripts that perform authorised, reversible test actions inside the VM.

```bash
sudo apt-get install -y openssh-server sshpass netcat-openbsd
sudo LINUXGUARD_TEST_PASSWORD='choose-a-test-password' ./lab/run_scenarios.sh ./lab-capture
sudo ./lab/capture_baseline.sh ./lab-baseline
linuxguard evaluate --dataset ./lab-capture --baseline ./lab-baseline
```

`run_scenarios.sh` creates a `lgtest` user, runs each benign and suspicious scenario 20 seconds apart, records the
time interval of every scenario in `labels.json` and copies the logs. Labels are defined independently of the
detectors. Because the scenarios run on a live system, events from background services that fall inside a scenario
interval are labelled with that scenario.

## Uninstall

```bash
sudo systemctl disable --now linuxguard
sudo rm -f /etc/systemd/system/linuxguard.service /etc/audit/rules.d/50-linuxguard.rules
sudo augenrules --load
sudo rm -rf /opt/linuxguard /etc/linuxguard /var/lib/linuxguard
```
