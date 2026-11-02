"""Synthetic checks for fixed-window feature extraction (Phase 7). Fixtures are hand-built."""

import io

from linuxguard.features import extract_windows, FEATURE_NAMES
from linuxguard.parser import parse_lines


def rec(kind, body, *, serial, epoch):
    return f"type={kind} msg=audit({epoch}:{serial}): {body}\n"


def events(text):
    out = parse_lines(io.StringIO(text), host="target").events
    for i, e in enumerate(out):  # extract_windows needs an id per event
        e["id"] = i + 1
    return out


def test_windows_align_to_epoch_boundaries_and_split_by_user():
    # Windows align to absolute epoch; boundaries fall at multiples of 60 (…100, …160).
    text = (rec("SYSCALL", 'uid=1000 auid=1000 success=yes exe="/usr/bin/ls" syscall=59 key="lg_exec"',
                serial="1", epoch="1700000100.000") +
            rec("SYSCALL", 'uid=1000 auid=1000 success=yes exe="/usr/bin/cat" syscall=59 key="lg_exec"',
                serial="2", epoch="1700000150.000") +  # same [100,160) window as the first
            rec("SYSCALL", 'uid=0 success=yes exe="/usr/bin/id" syscall=59 key="lg_exec"',
                serial="3", epoch="1700000210.000"))   # next window, different user
    rows = extract_windows(events(text), window_seconds=60)
    assert len(rows) == 2
    assert {r["user"] for r in rows} == {"1000", "0"}  # uid 1000 and uid 0 land in separate windows
    big = max(rows, key=lambda r: r["features"]["n_events"])
    assert big["user"] == "1000" and big["features"]["n_events"] == 2 and big["features"]["n_distinct_exe"] == 2
    assert rows[0]["window_end"] > rows[0]["window_start"]  # window spans forward in time


def test_feature_values_counts_and_ratios():
    text = (rec("SYSCALL", 'uid=1000 auid=1000 success=yes exe="/tmp/eviltool" syscall=59 key="lg_exec"',
                serial="1", epoch="1700000001.000") +
            rec("USER_AUTH", "pid=1 uid=0 exe=\"/usr/sbin/sshd\" msg='op=x addr=10.0.0.1 res=failed'",
                serial="2", epoch="1700000002.000") +
            rec("USER_AUTH", "pid=1 uid=0 exe=\"/usr/sbin/sshd\" msg='op=x addr=10.0.0.1 res=success'",
                serial="3", epoch="1700000003.000"))
    rows = extract_windows(events(text), window_seconds=60, baseline_exes={"/usr/bin/ls"})
    tmp = next(r for r in rows if r["features"]["n_tmp_exec"])
    assert tmp["features"]["n_tmp_exec"] == 1 and tmp["features"]["n_new_exe"] == 1
    auth = next(r for r in rows if r["features"]["n_auth_fail"])
    assert auth["features"]["n_auth_fail"] == 1 and auth["features"]["n_auth_ok"] == 1
    assert auth["features"]["auth_fail_ratio"] == 0.5 and auth["features"]["n_distinct_srcip"] == 1


def test_feature_names_cover_every_row_and_missing_fields_are_safe():
    text = rec("SYSCALL", 'success=yes key="lg_exec"', serial="1", epoch="1700000001.000")  # no exe/paths/cmdline
    rows = extract_windows(events(text), window_seconds=60)
    assert set(rows[0]["features"]) == set(FEATURE_NAMES)
    assert rows[0]["features"]["cmdline_len_mean"] == 0.0 and rows[0]["features"]["n_new_exe"] == 0
    assert rows[0]["event_ids"] == [1]
