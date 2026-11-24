import os

import httpx

from linuxguard.config import CloudSettings, OllamaSettings
from linuxguard.domain.alerts import Alert
from linuxguard.explanation.base import ConsentRequiredError, Explanation, ExplanationError
from linuxguard.explanation.prompting import build_prompt, redactor_for

LOCAL_PROVIDER = "local-llm"
CLOUD_PROVIDER = "cloud-llm"
MAX_RESPONSE_CHARACTERS = 4000


def _clean_response(text: object) -> str:
    if not isinstance(text, str) or not text.strip():
        raise ExplanationError("The language model returned an empty response")
    return text.strip()[:MAX_RESPONSE_CHARACTERS]


class OllamaExplainer:
    name = LOCAL_PROVIDER

    def __init__(self, settings: OllamaSettings, max_events: int = 20, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._max_events = max_events
        self._client = client or httpx.Client(timeout=settings.timeout_seconds)

    def explain(self, alert: Alert) -> Explanation:
        redactor = redactor_for(alert) if self._settings.redact else None
        prompt = build_prompt(alert, self._max_events, redactor)
        try:
            response = self._client.post(
                f"{self._settings.base_url.rstrip('/')}/api/generate",
                json={
                    "model": self._settings.model,
                    "system": prompt.system,
                    "prompt": prompt.user,
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
            )
            response.raise_for_status()
            text = _clean_response(response.json().get("response"))
        except (httpx.HTTPError, ValueError) as error:
            raise ExplanationError(f"local model unavailable: {error}") from error
        if redactor is not None:
            text = redactor.restore(text)
        return Explanation(text, LOCAL_PROVIDER, model=self._settings.model, disclosure="processed locally")


class CloudExplainer:
    name = CLOUD_PROVIDER

    def __init__(
        self,
        settings: CloudSettings,
        max_events: int = 20,
        consent_granted: bool | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings
        self._max_events = max_events
        self._consent_granted = settings.consent_granted if consent_granted is None else consent_granted
        self._client = client or httpx.Client(timeout=settings.timeout_seconds)

    def preview(self, alert: Alert) -> str:
        prompt = build_prompt(alert, self._max_events, redactor_for(alert))
        return prompt.user

    def explain(self, alert: Alert) -> Explanation:
        if not self._consent_granted:
            raise ConsentRequiredError("cloud explanations require explicit consent before evidence is sent")
        api_key = os.environ.get(self._settings.api_key_env)
        if not api_key:
            raise ExplanationError(f"environment variable {self._settings.api_key_env} is not set")
        redactor = redactor_for(alert)
        prompt = build_prompt(alert, self._max_events, redactor)
        try:
            response = self._client.post(
                self._settings.endpoint,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": self._settings.model,
                    "temperature": 0.2,
                    "messages": [
                        {"role": "system", "content": prompt.system},
                        {"role": "user", "content": prompt.user},
                    ],
                },
            )
            response.raise_for_status()
            choices = response.json().get("choices") or [{}]
            text = _clean_response(choices[0].get("message", {}).get("content"))
        except (httpx.HTTPError, ValueError, AttributeError, IndexError) as error:
            raise ExplanationError(f"cloud model unavailable: {type(error).__name__}") from error
        return Explanation(
            redactor.restore(text),
            CLOUD_PROVIDER,
            model=self._settings.model,
            disclosure="redacted evidence was processed by an external provider with user consent",
        )
