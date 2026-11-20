"""Optional natural-language alert explanations with a guaranteed non-AI fallback (Phase 11).

Three modes (proposal objective 6): `standard` uses a local template; `local` asks a locally
hosted model via Ollama; `cloud` is intentionally disabled here. The AI only produces text — it
never influences detection or runs commands — and any failure falls back to the template, so
detection, storage and reporting keep working whether or not a model is available. No data
leaves the host: `local` talks only to the Ollama endpoint (default localhost).
"""

import json
import urllib.request

_SYSTEM = (
    "You are a security analyst assistant. Explain ONLY from the evidence provided below. "
    "If something is not in the evidence, say \"unknown\" rather than guessing. Never suggest, "
    "recommend, or output shell commands. Do not invent facts, file names, users or IP addresses. "
    "Write 2-4 plain-English sentences: what happened and why it may be suspicious."
)


def _evidence_lines(evidence):
    lines = []
    for event in evidence[:20]:  # shortcut: cap context at 20 events; widen if alerts need more
        parts = [event.get("ts"), event.get("event_type"), f"exe={event.get('exe')}",
                 f"user={event.get('user')}", f"pid={event.get('pid')}"]
        for field in ("path", "syscall_name", "src_ip"):
            if event.get(field):
                parts.append(f"{field}={event[field]}")
        lines.append("- " + " ".join(str(p) for p in parts if p is not None))
    return "\n".join(lines) or "- (no evidence events)"


def _build_prompt(alert, evidence):
    source = alert.get("source")
    if alert.get("rule_id"):
        source = f"{source} {alert['rule_id']}"
    header = (f"Alert: {alert.get('title')}\nSource: {source}\n"
              f"Severity: {alert.get('severity')}\nDetection reason: {alert.get('reason')}")
    if alert.get("anomaly_score") is not None:
        header += f"\nAnomaly score: {alert['anomaly_score']}"
    return f"{_SYSTEM}\n\n{header}\n\nEvidence events:\n{_evidence_lines(evidence)}\n\nExplanation:"


def _template_explanation(alert, evidence):
    who = evidence[0].get("user") if evidence else None
    origin = ("rule " + alert["rule_id"]) if alert.get("source") == "rule" else "the anomaly detector"
    first = (f"{alert.get('title')}. Flagged by {origin} "
             f"({alert.get('severity')} severity) from {len(evidence)} audit event(s)"
             + (f" involving user {who}" if who else "") + ".")
    second = alert.get("reason", "")
    tail = ("This anomaly score indicates unusual activity, not a confirmed intrusion; review the evidence."
            if alert.get("source") == "ml" else
            "Confirm whether this action was authorised before treating it as an incident.")
    return " ".join(s for s in (first, second, tail) if s)


def _ollama_generate(prompt, model, endpoint, timeout):
    # think=false keeps reasoning models (e.g. Gemma thinking variants) from spending their token
    # budget on hidden reasoning and returning an empty answer; the thinking text is a last resort.
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "think": False,
                       "options": {"temperature": 0.2}}).encode()
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read())
    text = (data.get("response") or data.get("thinking") or "").strip()
    if not text:
        raise ValueError("empty response from model")
    return text


def explain(alert, evidence, *, mode="standard", model=None,
            endpoint="http://localhost:11434", timeout=120):
    """Return (explanation_text, mode_used). Falls back to the template on any AI failure."""
    if mode == "local":
        try:
            return _ollama_generate(_build_prompt(alert, evidence), model, endpoint, timeout), "local"
        except Exception:
            return _template_explanation(alert, evidence), "standard (fallback)"
    if mode == "cloud":
        return _template_explanation(alert, evidence), "standard (cloud disabled)"
    return _template_explanation(alert, evidence), "standard"
