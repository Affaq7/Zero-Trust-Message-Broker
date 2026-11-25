"""Agent registry: who each agent is, its role, keys, status and epoch.

The registry is the broker's trust anchor (docs/identity-spec.md section 5).
Roles are always taken from here, never from a message or a token. Records are
frozen snapshots; every change replaces the record under a lock. State lives
in memory only.

Amna's revocation code calls suspend(), revoke() and restore().
"""

import json
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from broker.identity.keys import jwk_thumbprint, public_key_from_jwk
from contracts.catalog import get_catalog

AgentStatus = Literal["active", "suspended", "revoked"]


class RegistryError(ValueError):
    """A registration that would make the registry inconsistent."""


class UnknownAgentError(KeyError):
    """The agent is not in the registry."""


@dataclass(frozen=True)
class Instance:
    """One running copy of an agent with its own key."""

    instance_id: str
    public_key: Ed25519PublicKey
    jkt: str


@dataclass(frozen=True)
class AgentRecord:
    """Snapshot of one agent. ``agent_uri`` is the agent name (FYP-I)."""

    agent_uri: str
    role: str
    status: AgentStatus = "active"
    epoch: int = 0
    instances: tuple[Instance, ...] = ()

    def instance_by_jkt(self, jkt: str) -> Instance | None:
        """The instance whose key has thumbprint ``jkt``, if any."""
        return next((i for i in self.instances if i.jkt == jkt), None)


class AgentRegistry:
    """In-memory registry of agents and their instances."""

    def __init__(self) -> None:
        self._records: dict[str, AgentRecord] = {}
        self._lock = threading.Lock()

    # --- reading ----------------------------------------------------------------

    def get(self, agent_uri: str) -> AgentRecord | None:
        """Current snapshot of ``agent_uri``, or None if it is not registered."""
        return self._records.get(agent_uri)

    def agents(self) -> list[str]:
        """Registered agent names, sorted."""
        return sorted(self._records)

    # --- registration -------------------------------------------------------------

    def add_instance(self, agent_uri: str, role: str, instance_id: str,
                     public_key: Ed25519PublicKey) -> AgentRecord:
        """Register one instance. Adding the same instance with the same key again is a no-op."""
        catalog = get_catalog()
        if agent_uri not in catalog.agents:
            raise RegistryError(f"unknown agent {agent_uri!r}")
        if role not in catalog.roles:
            raise RegistryError(f"unknown role {role!r}")
        jkt = jwk_thumbprint(public_key)
        with self._lock:
            self._check_key_unused(jkt, agent_uri, instance_id)
            record = self._records.get(agent_uri) or AgentRecord(agent_uri=agent_uri, role=role)
            if record.role != role:
                raise RegistryError(f"{agent_uri!r} already has role {record.role!r}, not {role!r}")
            existing = next((i for i in record.instances if i.instance_id == instance_id), None)
            if existing is not None:
                if existing.jkt != jkt:
                    raise RegistryError(f"instance {instance_id!r} already has a different key")
                return record
            instances = sorted((*record.instances, Instance(instance_id, public_key, jkt)),
                               key=lambda i: i.instance_id)   # fixed order, whatever the load order
            record = replace(record, instances=tuple(instances))
            self._records[agent_uri] = record
            return record

    def _check_key_unused(self, jkt: str, agent_uri: str, instance_id: str) -> None:
        for record in self._records.values():
            for inst in record.instances:
                if inst.jkt == jkt and (record.agent_uri, inst.instance_id) != (agent_uri, instance_id):
                    raise RegistryError(f"key already registered for {record.agent_uri}/{inst.instance_id}")

    @classmethod
    def from_credentials_dir(cls, keys_dir: Path) -> "AgentRegistry":
        """Build a registry from the public parts of keys/*.json (private keys are ignored)."""
        files = sorted(keys_dir.glob("*.json"))
        if not files:
            raise RegistryError(f"no credential files in {keys_dir.name}/; run scripts/issue_credentials.py")
        registry = cls()
        for path in files:
            data = json.loads(path.read_text(encoding="utf-8"))
            registry.add_instance(data["agent"], data["role"], data["instance_id"],
                                  public_key_from_jwk(data["public_jwk"]))
        return registry

    # --- status changes (Amna) ------------------------------------------------------

    def suspend(self, agent_uri: str) -> AgentRecord:
        """Temporarily block the agent. Keeps the epoch; never undoes a revocation."""
        return self._update(agent_uri, lambda r: r if r.status == "revoked" else replace(r, status="suspended"))

    def revoke(self, agent_uri: str) -> AgentRecord:
        """Block the agent and add 1 to its epoch, so every earlier token is stale.

        Revoking an already revoked agent changes nothing.
        """
        return self._update(
            agent_uri,
            lambda r: r if r.status == "revoked" else replace(r, status="revoked", epoch=r.epoch + 1),
        )

    def restore(self, agent_uri: str) -> AgentRecord:
        """Make the agent active again. The epoch stays, so revoked tokens stay invalid."""
        return self._update(agent_uri, lambda r: replace(r, status="active"))

    def _update(self, agent_uri: str, change) -> AgentRecord:
        with self._lock:
            record = self._records.get(agent_uri)
            if record is None:
                raise UnknownAgentError(agent_uri)
            new = change(record)
            self._records[agent_uri] = new
            return new
