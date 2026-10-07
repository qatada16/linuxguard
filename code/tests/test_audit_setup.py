from pathlib import Path
import os
import shlex
import subprocess

import pytest


CODE_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = [CODE_DIR / "scripts" / name for name in ("setup-audit.sh", "check-audit-triggers.sh")]
RULES = CODE_DIR / "config" / "audit" / "linuxguard.rules"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_setup_script_has_valid_shell_syntax(script):
    result = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="Tests unprivileged invocation")
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_setup_script_refuses_unprivileged_invocation(script):
    result = subprocess.run(["sh", str(script)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "sudo sh" in result.stderr
    assert "backed up" not in result.stdout


def test_audit_rules_cover_required_sources_without_destructive_controls():
    rules = [shlex.split(line, comments=True) for line in RULES.read_text().splitlines()]
    rules = [tokens for tokens in rules if tokens]
    assert all(tokens[0] in ("-b", "-a", "-w") for tokens in rules)
    assert all("never" not in " ".join(tokens) for tokens in rules)
    keys = {tokens[tokens.index("-k") + 1] for tokens in rules if "-k" in tokens}
    assert keys == {"lg_exec", "lg_mode", "lg_identity", "lg_priv", "lg_ssh", "lg_persist", "lg_shadow_read"}
    for arch in ("b64", "b32"):
        exec_rules = [tokens for tokens in rules if tokens[-1] == "lg_exec" and f"arch={arch}" in tokens]
        assert len(exec_rules) == 1
        assert set(exec_rules[0][exec_rules[0].index("-S") + 1].split(",")) == {"execve", "execveat"}
    assert any(tokens[:4] == ["-w", "/home/bonzo/.ssh", "-p", "wa"] for tokens in rules)
