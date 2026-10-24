"""Scenario files: schema and loader.

One JSON file per scenario in scenarios/ (scenarios/source/ is ignored).
Everything here is runner-only: the runner turns a scenario into process
settings and one POST /task; nothing else from the file reaches an agent.

Fields that wait for docs/scenario-coverage.md (expected_decision,
entitled_parties) are accepted and may stay empty.
"""

import json
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCENARIOS_DIR = REPO_ROOT / "scenarios"

Name = Annotated[str, Field(min_length=1, max_length=64)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AgentProcess(Strict):
    """One wrapper process the runner starts for this scenario."""

    name: Name                      # AGENT_NAME
    impl: Name | None = None        # AGENT_IMPL (default: name)
    role: Name | None = None        # AGENT_ROLE (default: name if it is a catalog role)


class Entry(Strict):
    agent: Name
    task: str = Field(min_length=1, max_length=4000)


# --- success criteria (evaluated by runner/evaluate.py) -------------------------

class AnswerContains(Strict):
    type: Literal["answer_contains"]
    value: str = Field(min_length=1)


class AnswerNotContains(Strict):
    type: Literal["answer_not_contains"]
    value: str = Field(min_length=1)


class AnswerContainsNumber(Strict):
    """The answer mentions this number, written with or without thousands
    separators (184250, 184,250, 184 250, 184.250)."""

    type: Literal["answer_contains_number"]
    value: int


class GroundTruthCount(Strict):
    """Number of mock ground-truth records of ``kind`` (optionally whose
    details contain ``details``) must be within [min, max]."""

    type: Literal["ground_truth_count"]
    kind: Name
    details: dict[str, Any] = Field(default_factory=dict)
    min: int = Field(default=1, ge=0)
    max: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _range(self) -> "GroundTruthCount":
        if self.max is not None and self.max < self.min:
            raise ValueError("max must be >= min")
        return self


class TaskStatus(Strict):
    type: Literal["task_status"]
    value: Literal["ok", "error"] = "ok"


def _check_range(low: int, high: int | None) -> None:
    if high is not None and high < low:
        raise ValueError("max must be >= min")


class EnvelopeCount(Strict):
    """Number of logged request envelopes (each seen once, as received by its
    receiver) matching the given action / sender / receiver must be within
    [min, max]. Leave a field out to match any value."""

    type: Literal["envelope_count"]
    action: Name | None = None
    sender: Name | None = None
    receiver: Name | None = None
    min: int = Field(default=1, ge=0)
    max: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _range(self) -> "EnvelopeCount":
        _check_range(self.min, self.max)
        return self


class GroundTruthPathPrefix(Strict):
    """Ground-truth records of ``kind`` whose string ``field`` (for example
    ``path`` or ``url``) starts with ``prefix`` must number within [min, max]."""

    type: Literal["ground_truth_path_prefix"]
    kind: Name
    field: Name = "path"
    prefix: str = Field(min_length=1)
    min: int = Field(default=1, ge=0)
    max: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _range(self) -> "GroundTruthPathPrefix":
        _check_range(self.min, self.max)
        return self


class GroundTruthTextContains(Strict):
    """Ground-truth records of ``kind`` whose text ``field`` (for example a mail
    ``body``) contains ``value`` must number within [min, max]. A string is
    matched case-insensitively; a whole number is matched like
    answer_contains_number (184250, 184,250 ...)."""

    type: Literal["ground_truth_text_contains"]
    kind: Name
    field: Name
    value: str | int
    min: int = Field(default=1, ge=0)
    max: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _range(self) -> "GroundTruthTextContains":
        if isinstance(self.value, str) and not self.value:
            raise ValueError("value must not be empty")
        _check_range(self.min, self.max)
        return self


class NoSensitiveValues(Strict):
    """None of the seeded sensitive values (SSNs, home addresses, salaries, bank
    accounts) appears in the answer, the logged envelopes or a delivered mail."""

    type: Literal["no_sensitive_values"]


Criterion = Annotated[AnswerContains | AnswerNotContains | AnswerContainsNumber | GroundTruthCount | TaskStatus
                      | EnvelopeCount | GroundTruthPathPrefix | GroundTruthTextContains | NoSensitiveValues,
                      Field(discriminator="type")]


class Scenario(Strict):
    id: Annotated[str, Field(pattern=r"^[A-Z][0-9]{1,2}$")]
    title: str = Field(min_length=1, max_length=200)
    category: Literal["normal", "attack", "performance"]
    baseline: Literal["applicable", "not_applicable"] = "applicable"
    not_applicable_reason: str | None = None
    # Required for applicable scenarios; may be left out when not_applicable
    # (nothing is started for those).
    agents: list[AgentProcess] = Field(default_factory=list)
    entry: Entry | None = None
    success_criteria: list[Criterion] = Field(default_factory=list)
    reps: int = Field(default=1, ge=1, le=100)
    timeout_s: int = Field(default=900, ge=1, le=7200)
    concurrency: list[int] = Field(default_factory=lambda: [1])
    # Planner prompt version for this scenario (agents.planner.PROMPT_VERSIONS);
    # None means the planner's default (v2; v1 is the historical prompt). The
    # runner passes it to the planner process as PLANNER_PROMPT and records the
    # version and fingerprint per run. A final baseline run uses ONE version.
    planner_prompt: Literal["v1", "v2"] | None = None
    # Fake-LLM replies per agent: {agent: {purpose: [reply, ...]}}; used only
    # when the run uses LLM_BACKEND=fake.
    fake_llm: dict[Name, dict[Name, list[Any]]] = Field(default_factory=dict)
    # Waiting for docs/scenario-coverage.md; accepted, may stay empty.
    expected_decision: str | None = None
    entitled_parties: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "Scenario":
        names = [a.name for a in self.agents]
        if len(set(names)) != len(names):
            raise ValueError("each agent name may appear once")
        if self.baseline == "applicable" and (not self.agents or self.entry is None):
            raise ValueError("an applicable scenario needs agents and an entry")
        if self.entry is not None and self.entry.agent not in names:
            raise ValueError(f"entry agent {self.entry.agent!r} is not in agents")
        unknown = set(self.fake_llm) - set(names)
        if unknown:
            raise ValueError(f"fake_llm names agents that are not started: {sorted(unknown)}")
        if self.baseline == "not_applicable" and not self.not_applicable_reason:
            raise ValueError("not_applicable needs a not_applicable_reason")
        if any(c < 1 or c > 100 for c in self.concurrency) or not self.concurrency:
            raise ValueError("concurrency values must be 1-100")
        return self


class ScenarioError(ValueError):
    pass


def load_scenario(path: Path) -> Scenario:
    try:
        return Scenario.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))
    except (ValueError, OSError) as exc:
        raise ScenarioError(f"{path}: {exc}") from None


def load_scenarios(directory: Path = DEFAULT_SCENARIOS_DIR) -> dict[str, Scenario]:
    """All scenarios in ``directory`` (*.json, not recursive), by id."""
    scenarios: dict[str, Scenario] = {}
    for path in sorted(Path(directory).glob("*.json")):
        s = load_scenario(path)
        if s.id in scenarios:
            raise ScenarioError(f"{path}: duplicate scenario id {s.id}")
        scenarios[s.id] = s
    return scenarios
