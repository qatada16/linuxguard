"""Synthetic (clearly labelled) fixtures for the Phase 6 rule engine.

Every event here is hand-built audit text, not experimental data. Each rule gets a
firing case and a realistic near-miss; thresholds, grouping isolation, missing fields,
evidence links, replay idempotency and the settle horizon are checked separately.
"""

import io
from pathlib import Path

import pytest

from linuxguard.parser import parse_lines
from linuxguard.rules import DetectionResult, detect, load_rules, _matches
from linuxguard.storage import EvidenceStore


RULES = load_rules(Path(__file__).resolve().parents[1] / "config" / "rules.yaml")
BY_ID = {rule["id"]: rule for rule in RULES}


def rec(kind, body="", *, serial="1", epoch="1700000000.125", enriched=""):
    return f"type={kind} msg=audit({epoch}:{serial}): {body}" + ("\x1d" + enriched if enriched else "") + "\n"


def event(*records, host="target"):
    events = parse_lines(io.StringIO("".join(records)), host=host).events
    assert len(events) == 1, events
    return events[0]


def path(item, name, nametype, mode="0100644"):
    return f'item={item} name="{name}" nametype={nametype} mode={mode}'


def syscall(key, *, syscall_no, success="yes", exe="/usr/bin/x", uid=0, args="", paths=(), serial="1", epoch="1700000000.125"):
    body = f'uid={uid} auid=1000 pid=100 ppid=1 success={success} exe="{exe}" syscall={syscall_no} {args} key="{key}"'
    records = [rec("SYSCALL", body, serial=serial, epoch=epoch)]
    records += [rec("PATH", entry, serial=serial, epoch=epoch) for entry in paths]
    return event(*records)


def fires(rule_id, ev):
    return _matches(BY_ID[rule_id]["match"], ev)


# ----- single-event match rules: one firing case and one near-miss each -----

def test_r01_shadow_read_by_unexpected_process():
    fire = syscall("lg_shadow_read", syscall_no=257, exe="/usr/bin/cat", args="a2=80000",
                   paths=[path(0, "/etc/shadow", "NORMAL", "0100640")])
    allowed = syscall("lg_shadow_read", syscall_no=257, exe="/usr/sbin/unix_chkpwd", args="a2=80000",
                      paths=[path(0, "/etc/shadow", "NORMAL", "0100640")])
    assert fires("R01", fire) and not fires("R01", allowed)


def test_r02_identity_write_outside_account_tools():
    fire = syscall("lg_identity", syscall_no=257, exe="/usr/bin/vi", args="a2=a0902",
                   paths=[path(0, "/etc/passwd", "NORMAL")])
    allowed = syscall("lg_identity", syscall_no=257, exe="/usr/sbin/usermod", args="a2=a0902",
                      paths=[path(0, "/etc/passwd", "NORMAL")])
    assert fires("R02", fire) and not fires("R02", allowed)


def test_r03_sudoers_create_but_not_delete_or_failure():
    fire = syscall("lg_priv", syscall_no=257, exe="/usr/bin/tee", args="a2=c2",
                   paths=[path(0, "/etc/sudoers.d/", "PARENT", "040755"), path(1, "/etc/sudoers.d/evil", "CREATE", "0100440")])
    deleted = syscall("lg_priv", syscall_no=263, exe="/usr/bin/rm",
                      paths=[path(0, "/etc/sudoers.d/", "PARENT", "040755"), path(1, "/etc/sudoers.d/evil", "DELETE", "0100440")])
    failed = syscall("lg_priv", syscall_no=257, success="no", exe="/usr/bin/tee", args="a2=c2",
                     paths=[path(0, "/etc/sudoers.d/evil", "CREATE")])
    assert fires("R03", fire) and not fires("R03", deleted) and not fires("R03", failed)


def test_r03_ignores_config_change_record():
    ev = event(rec("CONFIG_CHANGE", 'op=add_rule key="lg_priv" list=4 res=1'))
    assert not fires("R03", ev)


def test_r06_shell_by_service_account_not_user_or_root():
    svc = syscall("lg_exec", syscall_no=59, exe="/usr/bin/bash", uid=33)
    user = syscall("lg_exec", syscall_no=59, exe="/usr/bin/bash", uid=1000)
    root = syscall("lg_exec", syscall_no=59, exe="/usr/bin/bash", uid=0)
    assert fires("R06", svc) and not fires("R06", user) and not fires("R06", root)


def test_r07_execution_from_tmp_directly_or_as_script():
    direct = syscall("lg_exec", syscall_no=59, exe="/tmp/evil", uid=1000)
    script = syscall("lg_exec", syscall_no=59, exe="/usr/bin/bash", uid=1000,
                     paths=[path(0, "/dev/shm/payload.sh", "NORMAL")])
    benign = syscall("lg_exec", syscall_no=59, exe="/usr/bin/ls", uid=1000)
    assert fires("R07", direct) and fires("R07", script) and not fires("R07", benign)


def test_r08_persistence_file_created():
    fire = syscall("lg_persist", syscall_no=257, exe="/usr/bin/tee", args="a2=c2",
                   paths=[path(0, "/etc/cron.d/", "PARENT", "040755"), path(1, "/etc/cron.d/beacon", "CREATE")])
    deleted = syscall("lg_persist", syscall_no=263, exe="/usr/bin/rm",
                      paths=[path(0, "/etc/cron.d/beacon", "DELETE")])
    assert fires("R08", fire) and not fires("R08", deleted)


def test_r09_authorized_keys_but_not_known_hosts():
    fire = syscall("lg_ssh", syscall_no=257, exe="/usr/bin/tee", args="a2=a0902",
                   paths=[path(0, "/home/bonzo/.ssh/authorized_keys", "NORMAL")])
    known = syscall("lg_ssh", syscall_no=257, exe="/usr/bin/tee", args="a2=a0902",
                    paths=[path(0, "/home/bonzo/.ssh/known_hosts", "NORMAL")])
    assert fires("R09", fire) and not fires("R09", known)


def test_r10_suid_from_mode_argument_not_path_mode():
    fire = syscall("lg_mode", syscall_no=91, exe="/usr/bin/chmod", args="a1=9ed",
                   paths=[path(0, "/home/bonzo/rootbash", "NORMAL", "0100755")])
    plain = syscall("lg_mode", syscall_no=91, exe="/usr/bin/chmod", args="a1=1ed",
                    paths=[path(0, "/home/bonzo/rootbash", "NORMAL", "0104755")])
    assert fires("R10", fire) and not fires("R10", plain)


def test_match_rules_tolerate_missing_fields():
    for key, rid in [("lg_shadow_read", "R01"), ("lg_identity", "R02"), ("lg_mode", "R10"), ("lg_exec", "R06")]:
        ev = event(rec("SYSCALL", f'success=yes key="{key}"'))  # no exe, no paths, no args
        assert fires(rid, ev) is False


# ----- threshold rules: auth failure windows and success-after-failure -----

def auth(ok, *, serial, offset=0.0, addr="203.0.113.9", exe="/usr/lib/openssh/sshd-session", terminal="ssh", host="target"):
    res = "success" if ok else "failed"
    epoch = f"{1700000000 + offset:.3f}"
    addr_field = f"addr={addr} " if addr else ""
    body = (f'pid=1 uid=0 terminal={terminal} exe="{exe}" '
            f"msg='op=PAM:authentication acct=\"bonzo\" {addr_field}res={res}'")
    return rec("USER_AUTH", body, serial=serial, epoch=epoch)


def run(records, rule_ids, tmp_path, *, name="t", settled=True):
    events = parse_lines(io.StringIO("".join(records)), host="target").events
    store = EvidenceStore(tmp_path / f"{name}.db")
    store.insert_events(events)
    rules = [BY_ID[rid] for rid in rule_ids]
    result = detect(store, rules, settled=settled)
    return store, result


def test_r04_threshold_boundary(tmp_path):
    four = [auth(False, serial=str(i), offset=i) for i in range(4)]
    assert run(four, ["R04"], tmp_path, name="four")[1].new_alerts == 0
    five = [auth(False, serial=str(i), offset=i * 15.0) for i in range(5)]  # spans exactly 60.0 s
    assert run(five, ["R04"], tmp_path, name="five")[1].new_alerts == 1


def test_r04_window_edge_and_two_bursts(tmp_path):
    spread = [auth(False, serial=str(i), offset=i * 15.0003) for i in range(5)]  # spans 60.0012 s
    assert run(spread, ["R04"], tmp_path, name="spread")[1].new_alerts == 0
    ten = [auth(False, serial=str(i), offset=i) for i in range(10)]
    assert run(ten, ["R04"], tmp_path, name="ten")[1].new_alerts == 2


def test_r04_groups_are_isolated_by_source_and_host(tmp_path):
    two_ips = [auth(False, serial=str(i), offset=i, addr="198.51.100.1" if i % 2 else "203.0.113.9")
               for i in range(8)]  # 4 each, neither reaches 5
    assert run(two_ips, ["R04"], tmp_path, name="ips")[1].new_alerts == 0


def test_r04_missing_ip_falls_back_without_merging(tmp_path):
    # No addr: fall back to (host, exe, terminal). tty1 and /dev/tty1 normalize together.
    local = [auth(False, serial=str(i), offset=i, addr=None, exe="/usr/bin/login",
                  terminal="tty1" if i < 3 else "/dev/tty1") for i in range(5)]
    assert run(local, ["R04"], tmp_path, name="local")[1].new_alerts == 1
    split = [auth(False, serial=str(i), offset=i, addr=None, exe="/usr/bin/login",
                  terminal="tty1" if i < 3 else "pts/0") for i in range(5)]  # two terminals, 3 + 2
    assert run(split, ["R04"], tmp_path, name="split")[1].new_alerts == 0


def test_r05_success_after_failures(tmp_path):
    fire = [auth(False, serial=str(i), offset=i) for i in range(3)] + [auth(True, serial="9", offset=4)]
    store, result = run(fire, ["R05"], tmp_path, name="r05fire")
    assert result.new_alerts == 1
    alert_id = store.connection.execute("SELECT id FROM alerts").fetchone()[0]
    assert len(store.timeline(alert_id)) == 4  # three failures plus the success
    near = [auth(False, serial=str(i), offset=i) for i in range(2)] + [auth(True, serial="9", offset=4)]
    assert run(near, ["R05"], tmp_path, name="r05near")[1].new_alerts == 0


# ----- evidence links, replay idempotency, settle horizon -----

def test_alert_links_exact_triggering_event_id(tmp_path):
    fire = syscall("lg_priv", syscall_no=257, exe="/usr/bin/tee", args="a2=c2",
                   paths=[path(1, "/etc/sudoers.d/evil", "CREATE")])
    store = EvidenceStore(tmp_path / "evi.db")
    store.insert_events([fire])
    stored_id = store.connection.execute("SELECT id FROM events").fetchone()[0]
    detect(store, [BY_ID["R03"]], settled=True)
    alert_id = store.connection.execute("SELECT id FROM alerts").fetchone()[0]
    assert [row["id"] for row in store.timeline(alert_id)] == [stored_id]


def test_replay_adds_no_alerts_and_preserves_status(tmp_path):
    fire = syscall("lg_priv", syscall_no=257, exe="/usr/bin/tee", args="a2=c2",
                   paths=[path(1, "/etc/sudoers.d/evil", "CREATE")])
    store = EvidenceStore(tmp_path / "replay.db")
    store.insert_events([fire])
    detect(store, [BY_ID["R03"]], settled=True)
    store.connection.execute("UPDATE alerts SET status='investigating'")
    store.connection.commit()
    again = detect(store, [BY_ID["R03"]], settled=True)
    assert again.new_alerts == 0 and again.alerts == 1
    assert store.connection.execute("SELECT count(*) FROM alert_evidence").fetchone()[0] == 1
    assert store.connection.execute("SELECT status FROM alerts").fetchone()[0] == "investigating"


def test_settle_horizon_defers_then_fires(tmp_path):
    fire = syscall("lg_priv", syscall_no=257, exe="/usr/bin/tee", args="a2=c2", epoch="1700000100.000",
                   paths=[path(1, "/etc/sudoers.d/evil", "CREATE")])
    store = EvidenceStore(tmp_path / "settle.db")
    store.insert_events([fire])
    unsettled = detect(store, [BY_ID["R03"]], settle_seconds=10, settled=False)
    assert unsettled.new_alerts == 0 and unsettled.deferred == 1
    later = syscall("lg_exec", syscall_no=59, exe="/usr/bin/ls", uid=1000, serial="2", epoch="1700000200.000")
    store.insert_events([later])
    settled_now = detect(store, [BY_ID["R03"]], settle_seconds=10, settled=False)
    assert settled_now.new_alerts == 1 and settled_now.deferred == 1
    assert detect(store, [BY_ID["R03"]], settle_seconds=10, settled=False).new_alerts == 0


# ----- rule format validation -----

def test_shipped_rules_have_ten_unique_ids():
    assert len(RULES) == 10 and len({rule["id"] for rule in RULES}) == 10


@pytest.mark.parametrize("bad", [
    [{"id": "A", "title": "t", "severity": "high", "match": {"bogus": 1}}],
    [{"id": "A", "title": "t", "severity": "severe", "match": {"key": "k"}}],
    [{"id": "A", "title": "t", "severity": "high"}],
    [{"id": "A", "title": "t", "severity": "high", "match": {"key": "k"}, "threshold": {}}],
    [{"id": "A", "title": "t", "severity": "high", "match": {"key": "k"}},
     {"id": "A", "title": "t2", "severity": "low", "match": {"key": "k"}}],
    [{"id": "A", "title": "t", "severity": "high",
      "threshold": {"event_type": "USER_AUTH", "count": 1, "within_seconds": 60, "group_by": ["host"]}}],
    [{"id": "A", "title": "t", "severity": "high",
      "threshold": {"count": 5, "within_seconds": 60, "group_by": ["nope"]}}],
    {"not": "a list"},
])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(ValueError):
        load_rules(bad)
