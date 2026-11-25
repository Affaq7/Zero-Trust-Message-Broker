"""evaluate_policy(): pipeline step 4, may this sender call this action?

Pure rules, no model, the same answer every time (docs/identity-spec.md
sections 6 and 8). Inputs are the verified identity (step 2), the action
catalog (contracts/) and broker/policy/rules.yaml. Roles always come from the
verified identity and the registry, never from the message; free text such as
``justification`` is never read.

Order: identity and envelope rules, then the hard gates (UNKNOWN_ACTION,
PROHIBITED_ACTION, ROLE_NOT_ALLOWED, WRONG_RECEIVER), then delegation, then
the Conditional rules.
"""

import threading
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from broker.identity.registry import AgentRegistry
from broker.identity.verify import IdentityResult, default_verifier
from contracts.catalog import ActionCatalog, ActionSpec, get_catalog
from contracts.envelope import Envelope, rule_violations
from contracts.version import SCHEMA_VERSION

RULES_PATH = Path(__file__).with_name("rules.yaml")
USER = "user"

ActionClass = Literal["Permitted", "Conditional", "Prohibited", "Unknown"]


class PolicyResult(BaseModel):
    """Outcome of step 4."""

    model_config = ConfigDict(frozen=True)

    verdict: Literal["ALLOW", "DENY"]
    action_class: ActionClass
    reason_code: str
    needs_human: bool


class ConditionalRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    only_roles: tuple[str, ...]
    needs_human: bool = False


class PolicyRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[SCHEMA_VERSION]
    max_delegation_agents: int = Field(ge=1)
    conditional: dict[str, ConditionalRule]
    chain_exempt: tuple[str, ...] = ()


def load_rules(path: Path = RULES_PATH, catalog: ActionCatalog | None = None) -> PolicyRules:
    """Load rules.yaml and check it against the catalog; raises ValueError if it does not fit."""
    catalog = catalog or get_catalog()
    with open(path, encoding="utf-8") as f:
        rules = PolicyRules.model_validate(yaml.safe_load(f))   # ValidationError is a ValueError
    for action, rule in rules.conditional.items():
        spec = catalog.get(action)
        if spec is None:
            raise ValueError(f"rules.yaml: {action!r} is not in the catalog")
        if spec.action_class != "Conditional":
            raise ValueError(f"rules.yaml: {action!r} is {spec.action_class}, not Conditional")
        unknown = set(rule.only_roles) - set(catalog.roles)
        if unknown:
            raise ValueError(f"rules.yaml: {action!r} names unknown role(s) {sorted(unknown)}")
    for action in rules.chain_exempt:
        spec = catalog.get(action)
        if spec is None:
            raise ValueError(f"rules.yaml chain_exempt: {action!r} is not in the catalog")
        if spec.action_class != "Permitted":
            raise ValueError(f"rules.yaml chain_exempt: {action!r} is {spec.action_class}; only Permitted")
    missing = {a.name for a in catalog.actions if a.action_class == "Conditional"} - set(rules.conditional)
    if missing:
        raise ValueError(f"rules.yaml: no rule for Conditional action(s) {sorted(missing)}")
    return rules


class PolicyEngine:
    """Evaluates requests against one registry, catalog and rule set."""

    def __init__(self, registry: AgentRegistry, rules: PolicyRules | None = None,
                 catalog: ActionCatalog | None = None) -> None:
        self.registry = registry
        self.catalog = catalog or get_catalog()
        self.rules = rules or load_rules(catalog=self.catalog)

    def evaluate(self, env: Envelope, identity: IdentityResult) -> PolicyResult:
        """Decide ALLOW or DENY for one request. Raises ValueError for a response."""
        if env.msg_type != "request":
            raise ValueError("policy evaluates requests only; responses are checked in step 9")
        spec = self.catalog.get(env.action)
        action_class: ActionClass = spec.action_class if spec else "Unknown"
        reason = self._deny_reason(env, identity, spec)
        if reason is not None:
            return PolicyResult(verdict="DENY", action_class=action_class, reason_code=reason,
                                needs_human=False)
        rule = self.rules.conditional.get(env.action)
        if rule is not None and rule.needs_human:
            return PolicyResult(verdict="ALLOW", action_class=action_class,
                                reason_code="NEEDS_APPROVAL", needs_human=True)
        return PolicyResult(verdict="ALLOW", action_class=action_class,
                            reason_code="POLICY_ALLOW", needs_human=False)

    def _deny_reason(self, env: Envelope, identity: IdentityResult, spec: ActionSpec | None) -> str | None:
        """The first rule the request breaks, or None."""
        if not identity.ok:
            return identity.reason_code or "UNKNOWN_AGENT"
        if identity.agent != env.sender:
            return "SUB_MISMATCH"
        if rule_violations(env):
            return "RULE_VIOLATION"
        if spec is None:
            return "UNKNOWN_ACTION"
        if spec.action_class == "Prohibited":
            return "PROHIBITED_ACTION"
        permitted = self._permitted_roles(spec)
        if identity.role not in permitted:
            return "ROLE_NOT_ALLOWED"
        if env.receiver != spec.served_by:
            return "WRONG_RECEIVER"
        return self._delegation_reason(env, permitted)

    def _permitted_roles(self, spec: ActionSpec) -> set[str]:
        """Catalog allowed_roles, narrowed by the Conditional rule if there is one."""
        roles = set(spec.allowed_roles)
        rule = self.rules.conditional.get(spec.name)
        return roles & set(rule.only_roles) if rule is not None else roles

    def _delegation_reason(self, env: Envelope, permitted: set[str]) -> str | None:
        """Every agent in the chain must be registered and may itself call the action.

        A ``chain_exempt`` downstream step skips only the "may itself call" part.
        """
        agents = env.delegation_chain[1:]            # chain[0] is "user" (rule_violations)
        if len(agents) > self.rules.max_delegation_agents:
            return "DELEGATION_TOO_DEEP"
        exempt = env.action in self.rules.chain_exempt
        for agent in agents:
            record = self.registry.get(agent) if agent != USER else None
            if record is None or (not exempt and record.role not in permitted):
                return "DELEGATION_EXCEEDS_DELEGATOR"
        return None


# --- the broker's shared engine ------------------------------------------------------------

_default: PolicyEngine | None = None
_default_lock = threading.Lock()


def default_engine() -> PolicyEngine:
    """The broker's engine, using the same registry as the identity verifier."""
    global _default
    with _default_lock:
        if _default is None:
            _default = PolicyEngine(default_verifier().registry)
        return _default


def evaluate_policy(env: Envelope, identity: IdentityResult) -> PolicyResult:
    """Pipeline step 4 with the broker's shared registry, catalog and rules."""
    return default_engine().evaluate(env, identity)
