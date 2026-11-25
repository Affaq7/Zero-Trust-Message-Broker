"""K1: scripts/issue_credentials.py and broker/identity/tokens.py."""

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import jwt
import pytest
from pydantic import ValidationError

from broker.identity.keys import jwk_thumbprint, public_key_from_jwk
from broker.identity.registry import AgentRegistry
from broker.identity.tokens import TOKEN_LIFETIME_SECONDS, IdentityClaims
from contracts.tokens import BROKER_AUDIENCE, BROKER_ISSUER

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "issue_credentials.py"
EXPECTED_FILES = {"planner", "research", "database", "tool", "mailer", "research-2", "research-stolen"}


def load_script():
    spec = importlib.util.spec_from_file_location("issue_credentials", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


issue = load_script()


@pytest.fixture
def keys_dir(tmp_path):
    out = tmp_path / "keys"
    assert issue.main(["--out", str(out)]) == 0
    return out


def read(keys_dir, name):
    return json.loads((keys_dir / f"{name}.json").read_text(encoding="utf-8"))


def verified_claims(cred, **options):
    key = public_key_from_jwk(cred["public_jwk"])
    decoded = jwt.decode(cred["token"], key, algorithms=["EdDSA"], audience=BROKER_AUDIENCE,
                         issuer=BROKER_ISSUER, options=options)
    return IdentityClaims.model_validate(decoded)


# --- the 7 files ---------------------------------------------------------------------

def test_creates_exactly_seven_files(keys_dir):
    assert {p.stem for p in keys_dir.iterdir()} == EXPECTED_FILES


@pytest.mark.parametrize("name", sorted(EXPECTED_FILES))
def test_every_file_holds_a_valid_token_bound_to_its_key(keys_dir, name):
    cred = read(keys_dir, name)
    assert set(cred) == {"agent", "role", "instance_id", "epoch", "private_key", "public_jwk", "token"}
    claims = verified_claims(cred)                      # signature, iss, aud, exp all checked
    header = jwt.get_unverified_header(cred["token"])
    jkt = jwk_thumbprint(public_key_from_jwk(cred["public_jwk"]))
    assert header["alg"] == "EdDSA" and header["typ"] == "JWT"
    assert header["kid"] == claims.cnf.jkt == jkt
    assert (claims.sub, claims.role) == (cred["agent"], cred["role"])
    assert claims.epoch == cred["epoch"] == 0
    assert claims.exp - claims.iat == TOKEN_LIFETIME_SECONDS == 3600
    assert claims.nbf == claims.iat


def test_agents_and_instances(keys_dir):
    seen = {name: (read(keys_dir, name)["agent"], read(keys_dir, name)["instance_id"]) for name in EXPECTED_FILES}
    assert seen == {
        "planner": ("planner", "planner-1"), "database": ("database", "database-1"),
        "tool": ("tool", "tool-1"), "mailer": ("mailer", "mailer-1"),
        "research": ("research", "research-1"), "research-2": ("research", "research-2"),
        "research-stolen": ("research", "research-1"),
    }


def test_second_research_instance_has_its_own_key_and_token(keys_dir):
    one, two = read(keys_dir, "research"), read(keys_dir, "research-2")
    assert one["private_key"] != two["private_key"]
    assert one["token"] != two["token"]


def test_stolen_variant_is_a_byte_copy_of_research(keys_dir):
    assert (keys_dir / "research-stolen.json").read_bytes() == (keys_dir / "research.json").read_bytes()


def test_every_agent_has_its_own_key(keys_dir):
    keys = {read(keys_dir, n)["private_key"] for n in EXPECTED_FILES - {"research-stolen"}}
    assert len(keys) == 6


def test_registry_loads_the_public_parts(keys_dir):
    reg = AgentRegistry.from_credentials_dir(keys_dir)
    assert reg.agents() == ["database", "mailer", "planner", "research", "tool"]
    assert [i.instance_id for i in reg.get("research").instances] == ["research-1", "research-2"]
    for name in EXPECTED_FILES:
        cred = read(keys_dir, name)
        jkt = jwt.get_unverified_header(cred["token"])["kid"]
        assert reg.get(cred["agent"]).instance_by_jkt(jkt).instance_id == cred["instance_id"]


# --- overwrite protection ------------------------------------------------------------

def test_refuses_to_overwrite_without_force(keys_dir, capsys):
    before = read(keys_dir, "planner")
    assert issue.main(["--out", str(keys_dir)]) == 1
    assert "--force" in capsys.readouterr().err
    assert read(keys_dir, "planner") == before


def test_force_issues_new_keys(keys_dir):
    before = read(keys_dir, "planner")
    assert issue.main(["--out", str(keys_dir), "--force"]) == 0
    assert read(keys_dir, "planner")["private_key"] != before["private_key"]


def test_output_never_prints_keys_or_tokens(tmp_path, capsys):
    issue.main(["--out", str(tmp_path / "keys")])
    out = capsys.readouterr().out
    cred = read(tmp_path / "keys", "planner")
    assert cred["private_key"] not in out and cred["token"] not in out
    assert "7 credential files" in out


# --- --expired (A6) -------------------------------------------------------------------

def test_expired_prints_an_expired_token_signed_by_the_agents_key(keys_dir, capsys):
    assert issue.main(["--out", str(keys_dir), "--expired", "planner"]) == 0
    token = capsys.readouterr().out.strip()
    cred = {**read(keys_dir, "planner"), "token": token}
    with pytest.raises(jwt.ExpiredSignatureError):
        verified_claims(cred)
    claims = verified_claims(cred, verify_exp=False)    # signature is the real planner key
    assert claims.exp < int(time.time()) - 5
    assert claims.exp - claims.iat == TOKEN_LIFETIME_SECONDS
    assert claims.sub == "planner"


def test_expired_does_not_write_files(keys_dir, capsys):
    before = {p.name: p.read_bytes() for p in keys_dir.iterdir()}
    issue.main(["--out", str(keys_dir), "--expired", "planner"])
    assert {p.name: p.read_bytes() for p in keys_dir.iterdir()} == before


@pytest.mark.parametrize("name", ["ghost", "../planner"])
def test_expired_for_unknown_or_bad_name_fails(keys_dir, name, capsys):
    assert issue.main(["--out", str(keys_dir), "--expired", name]) == 1
    assert capsys.readouterr().out == ""


def test_script_runs_from_the_command_line(tmp_path):
    out = tmp_path / "keys"
    result = subprocess.run([sys.executable, str(SCRIPT), "--out", str(out)],
                            cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert len(list(out.glob("*.json"))) == 7


# --- IdentityClaims ---------------------------------------------------------------------

def claims_dict(**overrides):
    base = {"iss": BROKER_ISSUER, "aud": BROKER_AUDIENCE, "sub": "planner", "role": "planner",
            "iat": 1000, "nbf": 1000, "exp": 4600, "jti": "j1", "epoch": 0, "cnf": {"jkt": "a" * 43}}
    return {**base, **overrides}


def test_identity_claims_need_epoch():
    data = claims_dict()
    del data["epoch"]
    with pytest.raises(ValidationError):
        IdentityClaims.model_validate(data)


@pytest.mark.parametrize("bad", [{"epoch": -1}, {"epoch": "0"}, {"epoch": True}, {"trust_score": 1}])
def test_identity_claims_reject_bad_epoch_and_extra_claims(bad):
    with pytest.raises(ValidationError):
        IdentityClaims.model_validate(claims_dict(**bad))
