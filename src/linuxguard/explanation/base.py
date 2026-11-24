import time
from dataclasses import dataclass, field
from typing import Protocol

from linuxguard.domain.alerts import Alert


class ExplanationError(RuntimeError):
    pass


class ConsentRequiredError(ExplanationError):
    pass


@dataclass(frozen=True, slots=True)
class Explanation:
    text: str
    provider: str
    model: str | None = None
    disclosure: str | None = None
    fallback_reason: str | None = None
    generated_at: float = field(default_factory=time.time)

    @property
    def provider_label(self) -> str:
        label = self.provider if self.model is None else f"{self.provider} ({self.model})"
        if self.fallback_reason:
            label += f"; fallback because {self.fallback_reason}"
        if self.disclosure:
            label += f"; {self.disclosure}"
        return label


class Explainer(Protocol):
    name: str

    def explain(self, alert: Alert) -> Explanation: ...
