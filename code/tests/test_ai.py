"""AI explanation layer (Phase 11): offline tests with the model call mocked."""

import os

import pytest

from linuxguard import ai


ALERT = {"title": "Sudoers rule created or edited", "source": "rule", "rule_id": "R03",
         "severity": "high", "reason": "Sudoers rule created or edited: /usr/bin/tee on /etc/sudoers.d/evil"}
ML_ALERT = {"title": "Unusual activity for bonzo", "source": "ml", "rule_id": None, "severity": "medium",
            "reason": "unusual activity for bonzo: n_new_exe=12", "anomaly_score": -0.37}
EVIDENCE = [{"ts": "2026-11-28T07:21:18Z", "event_type": "SYSCALL", "exe": "/usr/bin/tee",
             "user": "bonzo", "pid": 2567, "path": "/etc/sudoers.d/evil", "syscall_name": "openat"}]


def test_standard_mode_uses_template_and_no_network(monkeypatch):
    monkeypatch.setattr(ai, "_ollama_generate", lambda *a, **k: (_ for _ in ()).throw(AssertionError("called")))
    text, mode = ai.explain(ALERT, EVIDENCE, mode="standard")
    assert mode == "standard" and ALERT["title"] in text and "bonzo" in text


def test_local_mode_returns_model_text(monkeypatch):
    monkeypatch.setattr(ai, "_ollama_generate", lambda prompt, model, endpoint, timeout: "MODEL SAYS: sudoers edit.")
    text, mode = ai.explain(ALERT, EVIDENCE, mode="local", model="gemma")
    assert mode == "local" and text == "MODEL SAYS: sudoers edit."


def test_local_failure_falls_back_to_template(monkeypatch):
    def boom(*a, **k):
        raise TimeoutError("ollama down")
    monkeypatch.setattr(ai, "_ollama_generate", boom)
    text, mode = ai.explain(ALERT, EVIDENCE, mode="local", model="gemma")
    assert mode == "standard (fallback)" and ALERT["title"] in text  # detection/reporting survive AI outage


def test_cloud_mode_is_disabled_with_fallback():
    text, mode = ai.explain(ML_ALERT, EVIDENCE, mode="cloud")
    assert mode == "standard (cloud disabled)" and "unusual activity" in text.lower()


def test_prompt_is_strict_and_grounded_in_evidence():
    prompt = ai._build_prompt(ALERT, EVIDENCE)
    assert "ONLY from the evidence" in prompt and "unknown" in prompt
    assert "Never suggest" in prompt and "/etc/sudoers.d/evil" in prompt and "R03" in prompt


@pytest.mark.skipif(os.environ.get("LINUXGUARD_OLLAMA_TEST") != "1",
                    reason="set LINUXGUARD_OLLAMA_TEST=1 to hit a live Ollama server")
def test_live_local_model():
    text, mode = ai.explain(ALERT, EVIDENCE, mode="local",
                            model=os.environ.get("LINUXGUARD_OLLAMA_MODEL", "gemma"), timeout=120)
    assert mode == "local" and len(text) > 10
