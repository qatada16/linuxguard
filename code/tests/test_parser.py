import io
import json
import subprocess
import sys

import pytest

from linuxguard.parser import load_user_names, parse_file, parse_lines


def record(kind, body="", *, serial="1", epoch="1700000000.125", node=None, enriched=""):
    prefix = f"node={node} " if node else ""
    return f"{prefix}type={kind} msg=audit({epoch}:{serial}): {body}" + ("\x1d" + enriched if enriched else "") + "\n"


def parse(text, **kwargs):
    return parse_lines(io.StringIO(text), host="target", **kwargs)


def test_interleaved_records_group_and_preserve_raw_evidence():
    syscall = record("SYSCALL", 'uid=0 auid=1000 pid=12 ppid=9 success=yes exe="/usr/bin/echo" key="lg_exec"')
    auth = record("USER_AUTH", "uid=0 auid=4294967295 msg='acct=\"alice\" addr=192.0.2.4 res=failed'", serial="2")
    args = record("EXECVE", 'argc=2 a0="echo" a1=68656c6c6f20776f726c64')
    cwd = record("CWD", 'cwd="/home/alice"')
    parent = record("PATH", 'item=0 name="." nametype=PARENT mode=040700')
    path = record("PATH", 'item=1 name="output.txt" nametype=CREATE mode=0100600')
    result = parse(syscall + auth + args + cwd + parent + path, users={1000: "alice", 0: "root"})
    assert result.records == 6 and result.malformed_lines == 0
    event, login = result.events
    assert event["raw"] == syscall + args + cwd + parent + path
    assert event["ts"] == "2023-11-14T22:13:20.125000Z"
    assert event["argv"] == ["echo", "hello world"]
    assert event["argv_complete"] is True
    assert event["cmdline"] == "echo 'hello world'"
    assert event["path"] == "/home/alice/output.txt"
    assert len(event["paths"]) == 2
    assert event["uid"] == 0 and event["auid"] == 1000 and event["user"] == "alice"
    assert login["success"] is False and login["src_ip"] == "192.0.2.4"
    assert login["auid"] is None and login["user"] == "root" and login["account"] == "alice"


def test_enriched_record_separator_is_not_a_new_line():
    raw = record("SYSCALL", 'uid=0 auid=1000 syscall=59 success=yes key="lg_exec"',
                 enriched='ARCH=x86_64 SYSCALL=execve AUID="alice" UID="root"')
    result = parse(raw)
    event, = result.events
    assert result.records == 1 and result.malformed_lines == 0
    assert event["user"] == "alice" and event["syscall_name"] == "execve"
    assert event["raw"] == raw


def test_fragmented_arguments_reassemble_bytes_before_utf8_decode():
    text = record("EXECVE", 'argc=2 a0="echo" a1_len=2 a1[0]=c3')
    text += record("EXECVE", "a1[1]=a9")
    event, = parse(text).events
    assert event["argv"] == ["echo", "é"]
    assert event["argv_complete"] is True


def test_incomplete_fragment_indexes_are_visible():
    event, = parse(record("EXECVE", 'argc=2 a0="echo" a1[1]=6869')).events
    assert event["argv_complete"] is False


def test_large_argc_does_not_allocate_missing_arguments():
    event, = parse(record("EXECVE", 'argc=999999999999 a0="echo"')).events
    assert event["argv"] == ["echo"] and event["argv_complete"] is False


def test_proctitle_and_hex_path_fallback():
    text = record("SYSCALL", "uid=1000 auid=-1 success=no")
    text += record("PROCTITLE", "proctitle=6563686f00686900")
    text += record("PATH", "name=2f746d702f68656c6c6f20776f726c64 nametype=NORMAL")
    event, = parse(text).events
    assert event["argv"] == ["echo", "hi"]
    assert event["argv_complete"] is False
    assert event["path"] == "/tmp/hello world"
    assert event["success"] is False and event["auid"] is None and event["user"] == "1000"


def test_same_serial_on_different_nodes_or_timestamps_is_separate():
    text = record("USER_START", "uid=0", node="one")
    text += record("USER_START", "uid=0", node="two")
    text += record("USER_START", "uid=0", node="one", epoch="1700000001.125")
    result = parse(text)
    assert len(result.events) == 3


def test_malformed_headers_timestamps_and_quotes_are_counted_and_skipped():
    text = "not an audit record\n" + record("SYSCALL", "uid=0", epoch="999999999999999999999999999")
    text += record("SYSCALL", 'exe="unterminated')
    text += record("USER_START", "uid=1000")
    result = parse(text)
    assert result.malformed_lines == 3 and result.records == 1 and len(result.events) == 1


def test_blank_lines_and_eoe_do_not_crash():
    result = parse("\n" + record("SYSCALL", "uid=0") + record("EOE"))
    assert result.malformed_lines == 0
    assert result.events[0]["record_types"] == ["SYSCALL", "EOE"]


def test_missing_user_and_unknown_record_remain_evidence():
    raw = record("UNKNOWN[9999]", "custom=value")
    event, = parse(raw).events
    assert event["user"] is None and event["success"] is None
    assert event["raw"] == raw


def test_target_passwd_mapping_and_repeatable_output(tmp_path):
    passwd = tmp_path / "target-passwd"
    passwd.write_text("alice:x:1000:1000::/home/alice:/bin/sh\ninvalid\n")
    assert load_user_names(passwd) == {1000: "alice"}
    source, output = tmp_path / "raw.audit", tmp_path / "events.jsonl"
    source.write_text(record("USER_START", "uid=1000"))
    parse_file(source, output, host="target", passwd_file=passwd)
    first = output.read_bytes()
    parse_file(source, output, host="target", passwd_file=passwd)
    assert output.read_bytes() == first
    assert json.loads(first)["user"] == "alice"
    assert output.stat().st_mode & 0o777 == 0o600


def test_parser_cannot_overwrite_raw_input(tmp_path):
    source = tmp_path / "raw.audit"
    source.write_text(record("USER_START", "uid=0"))
    with pytest.raises(ValueError, match="must differ"):
        parse_file(source, source)


def test_cli_parse(tmp_path):
    source, output = tmp_path / "raw.audit", tmp_path / "events.jsonl"
    source.write_text(record("USER_START", "uid=1000"))
    result = subprocess.run(
        [sys.executable, "-m", "linuxguard", "parse", "--file", str(source),
         "--output", str(output), "--host", "target"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "malformed lines: 0" in result.stdout
    assert json.loads(output.read_text())["host"] == "target"
