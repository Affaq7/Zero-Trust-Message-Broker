"""K1: the wrapper loads issued credentials from keys/ (wrapper/credentials.py).

File credentials are opt-in: only when the operator sets AGENT_CREDENTIALS.
Without it the wrapper keeps the old stub, so direct-mode runs are unchanged.
"""

import importlib.util
import json
from pathlib import Path

import jwt
import pytest

from broker.identity.keys import jwk_thumbprint, public_key_from_jwk
from broker.identity.registry import AgentRegistry
from broker.identity.tokens import IdentityClaims
from contracts.tokens import BROKER_AUDIENCE
from wrapper.app import create_app
from wrapper.config import Settings
from wrapper.credentials import CredentialsError, FileCredentials, StubCredentials, load_credentials

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "issue_credentials.py"

# credential file -> AGENT_NAME of the process that uses it
FILES = {"planner": "planner", "research": "research", "database": "database", "tool": "tool",
         "mailer": "mailer", "research-2": "research", "research-stolen": "research"}


@pytest.fixture(scope="module")
def keys_dir(tmp_path_factory):
    spec = importlib.util.spec_from_file_location("issue_credentials", SCRIPT)
    issue = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(issue)
    out = tmp_path_factory.mktemp("creds") / "keys"
    assert issue.main(["--out", str(out)]) == 0
    return out


def env_for(keys_dir, name):
    return {"AGENT_CREDENTIALS": name, "AGENT_KEYS_DIR": str(keys_dir)}


def test_without_agent_credentials_the_stub_is_used():
    assert isinstance(load_credentials("planner", "planner", environ={}), StubCredentials)


def test_loads_the_named_file_and_returns_its_token_for_every_receiver(keys_dir):
    creds = load_credentials("planner", "planner", environ=env_for(keys_dir, "planner"))
    file_token = json.loads((keys_dir / "planner.json").read_text())["token"]
    assert isinstance(creds, FileCredentials)
    assert creds.token_for("database") == creds.token_for("tool") == file_token
    assert (creds.sub, creds.role, creds.instance_id) == ("planner", "planner", "planner-1")
    assert creds.jkt == jwt.get_unverified_header(file_token)["kid"]


def test_private_key_matches_the_token_binding(keys_dir):
    creds = load_credentials("research", "research", environ=env_for(keys_dir, "research-2"))
    assert creds.instance_id == "research-2"
    assert jwk_thumbprint(creds.private_key.public_key()) == creds.jkt


@pytest.mark.parametrize("name", ["../planner", "planner.json", "Planner", ""])
def test_bad_names_rejected_or_ignored(keys_dir, name):
    env = env_for(keys_dir, name)
    if name == "":
        assert isinstance(load_credentials("planner", "planner", environ=env), StubCredentials)
    else:
        with pytest.raises(CredentialsError, match="invalid"):
            load_credentials("planner", "planner", environ=env)


def test_missing_file_is_a_clear_error(keys_dir):
    with pytest.raises(CredentialsError, match="issue_credentials"):
        load_credentials("planner", "planner", environ=env_for(keys_dir, "ghost"))


def test_file_for_another_agent_is_refused(keys_dir):
    with pytest.raises(CredentialsError, match="research"):
        load_credentials("planner", "planner", environ=env_for(keys_dir, "research"))


def test_file_with_another_role_is_refused(keys_dir):
    with pytest.raises(CredentialsError, match="role"):
        load_credentials("planner", "tool", environ=env_for(keys_dir, "planner"))


def test_broken_file_is_a_clear_error(tmp_path):
    (tmp_path / "planner.json").write_text("{not json", encoding="utf-8")
    env = {"AGENT_CREDENTIALS": "planner", "AGENT_KEYS_DIR": str(tmp_path)}
    with pytest.raises(CredentialsError, match="unreadable"):
        load_credentials("planner", "planner", environ=env)


@pytest.mark.parametrize("name, agent", sorted(FILES.items()))
def test_every_agent_wrapper_starts_and_gets_a_valid_token(keys_dir, monkeypatch, tmp_path, name, agent):
    """Done when: the testbed starts with the 7 files and every agent receives a valid token."""
    for key, value in env_for(keys_dir, name).items():
        monkeypatch.setenv(key, value)
    app = create_app(Settings(mode="direct", agent_name=agent, log_dir=tmp_path))
    token = app.state.runtime.token_for("database")

    record = AgentRegistry.from_credentials_dir(keys_dir).get(agent)
    instance = record.instance_by_jkt(jwt.get_unverified_header(token)["kid"])
    claims = IdentityClaims.model_validate(
        jwt.decode(token, instance.public_key, algorithms=["EdDSA"], audience=BROKER_AUDIENCE))
    assert (claims.sub, claims.role, claims.epoch) == (agent, record.role, record.epoch)
    assert claims.cnf.jkt == instance.jkt
    cred = json.loads((keys_dir / f"{name}.json").read_text())
    assert instance.instance_id == cred["instance_id"]
    assert public_key_from_jwk(cred["public_jwk"]).public_bytes_raw() == instance.public_key.public_bytes_raw()
