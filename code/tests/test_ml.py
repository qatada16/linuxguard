"""Synthetic Isolation Forest checks (Phase 7): fixtures are hand-built, not real data."""

import io

import pytest

from linuxguard import ml
from linuxguard.parser import parse_lines
from linuxguard.storage import EvidenceStore


# A varied normal-only baseline: changing counts, a pool of tools, and occasional benign
# failed auth / sudo, so the feature space has spread (as a real baseline would). A tight,
# zero-variance baseline is pathological for Isolation Forest and not representative.
TOOLS = ["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/bin/find", "/usr/bin/python3",
         "/usr/bin/vim", "/usr/bin/git", "/usr/bin/tar", "/usr/bin/sort", "/usr/bin/awk"]


def calm(n_windows, base=1700000000):
    import random
    lines = []
    serial = 0
    for w in range(n_windows):
        rng = random.Random(w)
        t = base + w * 60
        for i in range(rng.randint(2, 8)):
            serial += 1
            lines.append(f'type=SYSCALL msg=audit({t + i}.000:{serial}): uid=1000 auid=1000 '
                         f'success=yes exe="{rng.choice(TOOLS)}" syscall=59 cwd="/home/bonzo/d{rng.randint(0,4)}" key="lg_exec"\n')
        if rng.random() < 0.25:  # an occasional benign mistyped password
            serial += 1
            lines.append(f"type=USER_AUTH msg=audit({t + 30}.000:{serial}): pid=1 uid=1000 "
                         f"exe=\"/usr/bin/sudo\" msg='op=x res=failed'\n")
        if rng.random() < 0.3:   # an occasional legitimate sudo
            serial += 1
            lines.append(f'type=SYSCALL msg=audit({t + 40}.000:{serial}): uid=0 auid=1000 '
                         f'success=yes exe="/usr/bin/sudo" syscall=59 key="lg_exec"\n')
    return lines, serial, base + n_windows * 60


def store(tmp_path, name, lines):
    events = parse_lines(io.StringIO("".join(lines)), host="target").events
    s = EvidenceStore(tmp_path / name)
    s.insert_events(events)
    return s


def test_train_refuses_too_few_windows(tmp_path):
    lines, _, _ = calm(5)
    with pytest.raises(ValueError, match="windows"):
        ml.train(store(tmp_path, "tiny.db", lines), window_seconds=60, n_estimators=50,
                 random_state=42, threshold_percentile=1.0)


def test_anomalous_window_scores_below_threshold_but_calm_does_not(tmp_path):
    lines, serial, anomaly_t = calm(60)
    baseline = store(tmp_path, "base.db", lines)
    bundle = ml.train(baseline, window_seconds=60, n_estimators=200, random_state=42, threshold_percentile=1.0)
    # test capture = the same calm windows plus one burst of never-seen exes and failed auth
    burst = list(lines)
    for i in range(20):
        serial += 1
        burst.append(f'type=SYSCALL msg=audit({anomaly_t + i}.000:{serial}): '
                     f'uid=1000 auid=1000 success=yes exe="/opt/x{i}" syscall=59 key="lg_exec"\n')
        serial += 1
        burst.append(f"type=USER_AUTH msg=audit({anomaly_t + i}.500:{serial}): pid=1 uid=1000 "
                     f"exe=\"/usr/sbin/sshd\" msg='op=x addr=10.0.0.9 res=failed'\n")
    test = store(tmp_path, "test.db", burst)
    result = ml.score(test, bundle, settled=True)
    assert result.new_alerts >= 1
    rows = test.connection.execute("SELECT source, severity, rule_id, anomaly_score, reason FROM alerts").fetchall()
    assert rows and all(r["source"] == "ml" and r["rule_id"] is None for r in rows)
    assert all(r["anomaly_score"] is not None and "unusual" in r["reason"] and "intrusion" not in r["reason"]
               for r in rows)
    alert_id = test.connection.execute("SELECT id FROM alerts").fetchone()[0]
    assert len(test.timeline(alert_id)) >= 1  # evidence links to the window's events


def test_replay_is_idempotent_and_settle_defers_newest(tmp_path):
    lines, serial, anomaly_t = calm(60)
    base = store(tmp_path, "b2.db", lines)
    bundle = ml.train(base, window_seconds=60, n_estimators=120, random_state=42, threshold_percentile=1.0)
    burst = list(lines)
    for i in range(20):
        serial += 1
        burst.append(f'type=SYSCALL msg=audit({anomaly_t + i}.000:{serial}): uid=1000 auid=1000 '
                     f'success=yes exe="/opt/y{i}" syscall=59 key="lg_exec"\n')
    test = store(tmp_path, "t2.db", burst)
    first = ml.score(test, bundle, settled=True)
    again = ml.score(test, bundle, settled=True)
    assert again.new_alerts == 0 and again.alerts == first.alerts
    unsettled = ml.score(test, bundle, settle_seconds=10, settled=False)
    assert unsettled.deferred >= 1  # the final window is within the settle horizon
