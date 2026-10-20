"""Loads and validates the action catalog (contracts/action_catalog.yaml).

The catalog is policy data for the BROKER. Direct mode never consults it.
Default-deny: an action that is not in the catalog is never allowed.
served_by and the agents/roles lists are provisional (docs/open-questions.md).
"""

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from contracts.version import SCHEMA_VERSION

CATALOG_PATH = Path(__file__).with_name("action_catalog.yaml")

ActionName = Annotated[str, Field(pattern=r"^[a-z]+\.[a-z_]+$")]
ActionClass = Literal["Permitted", "Conditional", "Prohibited"]


class ActionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    name: ActionName
    action_class: ActionClass = Field(alias="class")
    allowed_roles: tuple[str, ...]
    served_by: str | None

    @model_validator(mode="after")
    def _roles_match_class(self) -> "ActionSpec":
        if len(set(self.allowed_roles)) != len(self.allowed_roles):
            raise ValueError(f"{self.name}: duplicate role in allowed_roles")
        if self.action_class == "Prohibited":
            if self.allowed_roles or self.served_by is not None:
                raise ValueError(f"{self.name}: Prohibited needs no roles and served_by null")
        elif not self.allowed_roles or self.served_by is None:
            raise ValueError(f"{self.name}: {self.action_class} needs roles and served_by")
        return self


class ActionCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[SCHEMA_VERSION]
    roles: tuple[str, ...]
    agents: tuple[str, ...]
    actions: tuple[ActionSpec, ...]

    @model_validator(mode="after")
    def _cross_checks(self) -> "ActionCatalog":
        names = [a.name for a in self.actions]
        if len(set(names)) != len(names):
            raise ValueError("duplicate action name in catalog")
        for spec in self.actions:
            unknown = set(spec.allowed_roles) - set(self.roles)
            if unknown:
                raise ValueError(f"{spec.name}: unknown roles {sorted(unknown)}")
            if spec.served_by is not None and spec.served_by not in self.agents:
                raise ValueError(f"{spec.name}: served_by {spec.served_by!r} is not an agent")
        return self

    def get(self, action: str) -> ActionSpec | None:
        return next((a for a in self.actions if a.name == action), None)

    def names(self) -> set[str]:
        return {a.name for a in self.actions}

    def is_allowed(self, role: str, action: str) -> bool:
        """Role-based check only (Conditional conditions are the broker's job)."""
        spec = self.get(action)
        return spec is not None and role in spec.allowed_roles

    def served_by(self, action: str) -> str | None:
        spec = self.get(action)
        return spec.served_by if spec else None


def load_catalog(path: Path = CATALOG_PATH) -> ActionCatalog:
    with open(path, encoding="utf-8") as f:
        return ActionCatalog.model_validate(yaml.safe_load(f))


@lru_cache(maxsize=1)
def get_catalog() -> ActionCatalog:
    """The repo's catalog, loaded once."""
    return load_catalog()
