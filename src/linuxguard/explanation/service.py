from linuxguard.config import ExplanationSettings
from linuxguard.detection.rules.model import Rule
from linuxguard.domain.alerts import Alert
from linuxguard.explanation.base import Explainer, Explanation, ExplanationError
from linuxguard.explanation.language_models import CloudExplainer, OllamaExplainer
from linuxguard.explanation.templates import TemplateExplainer

STANDARD_MODE = "template"
LOCAL_MODE = "local"
CLOUD_MODE = "cloud"


class ExplanationService:
    def __init__(self, primary: Explainer | None, fallback: TemplateExplainer) -> None:
        self._primary = primary
        self._fallback = fallback

    def explain(self, alert: Alert) -> Explanation:
        if self._primary is None:
            return self._fallback.explain(alert)
        try:
            return self._primary.explain(alert)
        except ExplanationError as error:
            fallback = self._fallback.explain(alert)
            return Explanation(
                text=fallback.text,
                provider=fallback.provider,
                fallback_reason=str(error),
            )


def create_explanation_service(
    settings: ExplanationSettings,
    rules: list[Rule],
    mode: str | None = None,
    cloud_consent: bool | None = None,
) -> ExplanationService:
    selected = mode or settings.mode
    fallback = TemplateExplainer(rules)
    if selected == STANDARD_MODE:
        return ExplanationService(None, fallback)
    if selected == LOCAL_MODE:
        return ExplanationService(OllamaExplainer(settings.ollama, settings.max_evidence_events), fallback)
    if selected == CLOUD_MODE:
        explainer = CloudExplainer(settings.cloud, settings.max_evidence_events, consent_granted=cloud_consent)
        return ExplanationService(explainer, fallback)
    raise ValueError(f"Unknown explanation mode: {selected}")
