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


class AppendQueryResult(Strict):
    """Compromised database (agents/malicious.py): after the honest reply to ``on_action``,
    run one extra read against the mock DB and append its rows. The leaked rows are real
    seeded data fetched at run time, never written into this file."""

    deviation: Literal["append_query_result"]
    on_action: str = "db.query_aggregate"
    resource: str = Field(min_length=1)           # e.g. "db:payroll"
    payload: dict[str, Any] = Field(default_factory=dict)


class AddRecipient(Strict):
    """Compromised tool (agents/malicious.py): add one recipient to the mail.deliver before it
    reaches the mailer. Use only a reserved example domain (e.g. someone@example.test)."""

    deviation: Literal["add_recipient"]
    field: Literal["to", "cc", "bcc"] = "bcc"
    address: str = Field(min_length=3, max_length=254)


# The one controlled deviation a compromised responder applies; honest in every other way.
Behaviour = Annotated[AppendQueryResult | AddRecipient, Field(discriminator="deviation")]


class AgentProcess(Strict):
    """One wrapper process the runner starts for this scenario."""

    name: Name                      # AGENT_NAME
    impl: Name | None = None        # AGENT_IMPL (default: name)
    role: Name | None = None        # AGENT_ROLE (default: name if it is a catalog role)
    # Fault-injection deviation for a compromised responder; only with impl "malicious".
    behaviour: Behaviour | None = None


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


class SensitiveValuesPresent(Strict):
    """At least ``min`` seeded sensitive values appear in the outcome (the answer, the logged
    reply envelopes or delivered mail). The inverse of no_sensitive_values: an attack scenario
    uses it to show a leak really happened (HTTP 200 alone is never enough)."""

    type: Literal["sensitive_values_present"]
    min: int = Field(default=1, ge=1)


class ScriptStepStatus(Strict):
    """The HTTP status code of scripted step N must equal ``value``."""

    type: Literal["script_step_status"]
    step: int = Field(ge=0)
    value: int


class ScriptStepBodyContains(Strict):
    """The JSON-serialised response body of scripted step N must contain ``value``."""

    type: Literal["script_step_body_contains"]
    step: int = Field(ge=0)
    value: str = Field(min_length=1)


class ScriptStepBodyNotContains(Strict):
    """The JSON-serialised response body of scripted step N must NOT contain ``value``."""

    type: Literal["script_step_body_not_contains"]
    step: int = Field(ge=0)
    value: str = Field(min_length=1)


class ScriptAllStepsStatus(Strict):
    """Every scripted step must return the given HTTP status code."""

    type: Literal["script_all_steps_status"]
    value: int


class ScriptStepPayloadStatus(Strict):
    """response_body.payload.status of scripted step N must equal ``value``.

    Agents answer HTTP 200 even when the action failed (status "error"), so
    the HTTP code alone does not show that the action ran."""

    type: Literal["script_step_payload_status"]
    step: int = Field(ge=0)
    value: Literal["ok", "error"]


Criterion = Annotated[AnswerContains | AnswerNotContains | AnswerContainsNumber | GroundTruthCount | TaskStatus
                      | EnvelopeCount | GroundTruthPathPrefix | GroundTruthTextContains | NoSensitiveValues
                      | SensitiveValuesPresent | ScriptStepStatus | ScriptStepBodyContains | ScriptStepBodyNotContains
                      | ScriptAllStepsStatus | ScriptStepPayloadStatus,
                      Field(discriminator="type")]


# --- scripted-attack definitions (used by agents/scripted.py) -----------------

class ScriptStep(Strict):
    """One HTTP request the scripted attacker sends."""

    receiver: Name
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    sender: Name | None = None
    sender_role: Name | None = None
    msg_type: Literal["request", "response"] = "request"
    delegation_chain: list[str] | None = None
    # direct mode: valid / expired / wrong_key / missing stub tokens (nothing checks them).
    # broker mode: valid = the sender's issued token and a proof with its own key; expired = a
    # token that expired an hour ago (A6); stolen = research-stolen.json's token with a proof
    # signed by a fresh key (A14); reissued = a new token with epoch ``token_epoch`` (A10);
    # missing = no Authorization header and no proof.
    token: Literal["valid", "expired", "wrong_key", "missing", "stolen", "reissued"] = "valid"
    token_epoch: int | None = Field(default=None, ge=0)
    # broker mode only: send straight to the receiver's own port instead of the broker (A12).
    bypass_broker: bool = False
    extra_fields: dict[str, Any] = Field(default_factory=dict)
    pause_ms: int = Field(default=0, ge=0, le=10000)

    @model_validator(mode="after")
    def _epoch_for_reissued(self) -> "ScriptStep":
        if (self.token == "reissued") != (self.token_epoch is not None):
            raise ValueError("token_epoch is required for token 'reissued' and only for it")
        return self


class AdminStep(Strict):
    """Broker mode only: an operator call the RUNNER makes between attack steps, with the run's
    admin token (the attacker process never sees it): POST /admin/<admin> on the broker."""

    admin: Literal["release", "revoke", "restore"]
    agent: Name
    by: Name                         # the reviewer (release) or the operator named in the audit log


class ScriptedAttack(Strict):
    """Configuration for the scripted attacker subprocess."""

    sender: Name
    sender_role: Name
    steps: list[ScriptStep | AdminStep] = Field(min_length=1, max_length=50)

    @property
    def requests(self) -> list[ScriptStep]:
        return [s for s in self.steps if isinstance(s, ScriptStep)]


# --- what the broker is expected to do (broker mode, evidence-based scoring) ---------------------

BrokerDecision = Literal["ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE"]


class ExpectedBrokerDecision(Strict):
    decision: BrokerDecision
    reason_code: str = Field(min_length=1)


class ExpectedBroker(Strict):
    """What the broker must do with this scenario under --mode broker. Scored from evidence: the
    broker's decisions for the trace (broker_decisions.jsonl and the audit log) must equal
    ``decisions`` in the order the broker finished them, the audit log must hold ``audit_events``
    and verify, the scripted requests must get ``http_status``, and /api/state must show
    ``final_quarantined`` at the end."""

    # applicable: run and score in broker mode; pending_f3: needs the content checks (F3), not run
    # yet; not_applicable: no broker mechanism to test (reason says why).
    status: Literal["applicable", "pending_f3", "not_applicable"] = "applicable"
    reason: str | None = None
    expected_decision: str = Field(min_length=1)          # text from docs/scenario-control-map.md section 3
    decisions: list[ExpectedBrokerDecision] | None = None  # None: not scored automatically (live model)
    audit_events: list[Literal["quarantine", "release", "revoke", "restore"]] = Field(default_factory=list)
    http_status: list[int] | None = None                   # per scripted request, in order (admin steps left out)
    final_quarantined: dict[Name, bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _reason_when_not_run(self) -> "ExpectedBroker":
        if self.status != "applicable" and not self.reason:
            raise ValueError(f"expected_broker status {self.status} needs a reason")
        return self


# --- fake-LLM definitions ----------------------------------------------------

class FakeRule(Strict):
    if_prompt_contains: str = Field(min_length=1)
    reply: Any


class FakeRules(Strict):
    rules: list[FakeRule] = Field(default_factory=list)
    default: Any = None

    @model_validator(mode="after")
    def _something(self) -> "FakeRules":
        if not self.rules and self.default is None:
            raise ValueError("fake rules need at least one rule or a default")
        return self


class Scenario(Strict):
    id: Annotated[str, Field(pattern=r"^[A-Z][0-9]{1,2}$")]
    title: str = Field(min_length=1, max_length=200)
    category: Literal["normal", "attack", "performance"]
    # not_applicable: direct mode has no such mechanism (nothing runs, left out of every rate).
    # not_executed: defined, but the testbed cannot run it yet (nothing runs, left out of every rate,
    # reported under its own status with the reason).
    baseline: Literal["applicable", "not_applicable", "not_executed"] = "applicable"
    not_applicable_reason: str | None = None
    not_executed_reason: str | None = None
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
    # A purpose maps to a list (replies consumed in order) or, for concurrent tasks, to rules
    # {"rules": [{"if_prompt_contains": ..., "reply": ...}], "default": reply} (not consumed).
    fake_llm: dict[Name, dict[Name, list[Any] | FakeRules]] = Field(default_factory=dict)
    # Scripted-attack definition (mutually exclusive with entry).
    scripted: ScriptedAttack | None = None
    # Waiting for docs/scenario-coverage.md; accepted, may stay empty.
    expected_decision: str | None = None
    entitled_parties: dict[str, Any] | None = None
    # What the broker must do under --mode broker (None: not scored in broker mode).
    expected_broker: ExpectedBroker | None = None

    def broker_status(self) -> str:
        """applicable / not_applicable / not_executed / pending_f3 under --mode broker."""
        if self.expected_broker is not None:
            return self.expected_broker.status
        return self.baseline

    @model_validator(mode="after")
    def _consistent(self) -> "Scenario":
        names = [a.name for a in self.agents]
        if len(set(names)) != len(names):
            raise ValueError("each agent name may appear once")
        if self.scripted is not None and self.entry is not None:
            raise ValueError("a scenario must use either entry or scripted, not both")
        if self.baseline == "applicable":
            if not self.agents:
                raise ValueError("an applicable scenario needs agents")
            if self.entry is None and self.scripted is None:
                raise ValueError("an applicable scenario needs an entry or scripted block")
        if self.entry is not None and self.entry.agent not in names:
            raise ValueError(f"entry agent {self.entry.agent!r} is not in agents")
        if self.scripted is not None:
            for i, step in enumerate(self.scripted.steps):
                if isinstance(step, AdminStep):
                    if self.expected_broker is None:
                        raise ValueError(f"scripted step {i} is an admin step: only for broker-mode scenarios")
                elif step.receiver not in names:
                    raise ValueError(f"scripted step {i} receiver {step.receiver!r} is not in agents")
        if self.broker_status() == "applicable" and (not self.agents or (self.entry is None and self.scripted is None)):
            raise ValueError("a scenario run in broker mode needs agents and an entry or scripted block")
        for a in self.agents:
            if a.behaviour is not None and a.impl != "malicious":
                raise ValueError(f"agent {a.name!r} has a behaviour block but impl is not 'malicious'")
        unknown = set(self.fake_llm) - set(names)
        if unknown:
            raise ValueError(f"fake_llm names agents that are not started: {sorted(unknown)}")
        if self.baseline == "not_applicable" and not self.not_applicable_reason:
            raise ValueError("not_applicable needs a not_applicable_reason")
        if self.baseline == "not_executed" and not self.not_executed_reason:
            raise ValueError("not_executed needs a not_executed_reason")
        if self.baseline != "not_executed" and self.not_executed_reason:
            raise ValueError("not_executed_reason is only for baseline not_executed")
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
