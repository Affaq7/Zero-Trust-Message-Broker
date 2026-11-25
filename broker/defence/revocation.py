"""Revocation (task A3, Amna). Scenario A10.

revoke(agent) calls Kissa's AgentRegistry.revoke(): status "revoked" and epoch
+ 1, so every token issued before is stale. restore(agent) calls
AgentRegistry.restore(): status "active" again, epoch kept. Per
docs/identity-spec.md (section 7 and the A10 row, Kissa's check order with
the epoch first), the identity step then answers STALE_EPOCH for every token
issued before the revoke, also after a restore, until a new token is issued
with the new epoch. A new token for an agent that is still revoked gets
AGENT_REVOKED.

The broker app calls set_registry() once at startup with its registry; tests
plug in their own. Interface fixed on 25 Nov (context file, section 7).
"""

from broker.identity.registry import AgentRegistry

_registry: AgentRegistry | None = None


def set_registry(registry: AgentRegistry | None) -> None:
    """Choose the registry that revoke() and restore() act on (None clears it)."""
    global _registry
    _registry = registry


def _current() -> AgentRegistry:
    if _registry is None:
        raise RuntimeError("no registry set: call set_registry() at broker startup")
    return _registry


def revoke(agent: str) -> None:
    """Revoke the agent: status revoked, epoch + 1 (registry.revoke())."""
    _current().revoke(agent)


def restore(agent: str) -> None:
    """Make the agent active again; the epoch stays (registry.restore())."""
    _current().restore(agent)
