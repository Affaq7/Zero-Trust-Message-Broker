"""Task A4: signed, hash-chained audit log (broker/audit/).

Done-when: editing one line of the file makes the verify command fail and print
that line number; docs/audit-log-examples.md is in the repo.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.audit import log as audit
from broker.audit import signing_key
from broker.audit.examples import entries as example_entries
from broker.audit.log import GENESIS_HASH, AuditLog, canonical, payload_hash
from broker.audit.verify import main as verify_main
from broker.audit.verify import verify_chain
from broker.identity.keys import public_jwk, public_key_from_jwk

REPO = Path(__file__).resolve().parents[2]
EXAMPLES_DOC = REPO / "docs" / "audit-log-examples.md"


def decision(**over):
    e = {"kind": "decision", "ts": "2026-11-25T19:00:00.000+00:00", "trace_id": "t1",
         "msg_id": "m1", "sender": "planner", "receiver": "database",
         "action": "db.query_aggregate", "decision": "ALLOW", "reason_code": "POLICY_ALLOW"}
    return e | over


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def path(tmp_path):
    return tmp_path / "broker_audit.jsonl"


def write_n(path, key, n=5):
    log = AuditLog(path, key)
    return [log.append(decision(msg_id=f"m{i}")) for i in range(1, n + 1)]


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def put(path, rows):
    path.write_text("".join(r + "\n" for r in rows), encoding="utf-8")


# --- append and the chain -------------------------------------------------------

def test_append_returns_the_entry_hash_and_chains(path, key):
    hashes = write_n(path, key, 3)
    recs = [json.loads(x) for x in lines(path)]
    assert [r["entry_hash"] for r in recs] == hashes
    assert [r["seq"] for r in recs] == [1, 2, 3]
    assert recs[0]["prev_hash"] == GENESIS_HASH
    assert recs[1]["prev_hash"] == hashes[0] and recs[2]["prev_hash"] == hashes[1]
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes)


def test_every_line_is_signed_and_verifies(path, key):
    write_n(path, key)
    r = verify_chain(path, key.public_key())
    assert (r.ok, r.lines, r.bad_line) == (True, 5, None)


def test_chain_continues_after_restart(path, key):
    write_n(path, key, 2)
    AuditLog(path, key).append(decision(msg_id="m3"))
    assert [json.loads(x)["seq"] for x in lines(path)] == [1, 2, 3]
    assert verify_chain(path, key.public_key()).ok


def test_all_fields_are_present_on_every_line(path, key):
    AuditLog(path, key).append(decision())
    rec = json.loads(lines(path)[0])
    assert set(rec) == set(audit.DECISION_FIELDS) | {"seq", "prev_hash", "entry_hash", "signature"}



def test_ts_defaults_to_now(path, key):
    e = decision()
    del e["ts"]
    AuditLog(path, key).append(e)
    assert json.loads(lines(path)[0])["ts"].endswith("+00:00")


# --- what may and may not be written ------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"payload": {"x": 1}},                 # the payload itself, never stored
    {"token": "fake-token"},               # a token
    {"scenario": "A9"},                    # a scenario label
    {"decision": "MAYBE"},
    {"kind": "nope"},
    {"msg_id": None},
    {"sender": ""},
])
def test_bad_entries_are_refused(path, key, bad):
    with pytest.raises(ValueError):
        AuditLog(path, key).append(decision(**bad))
    assert not path.exists()


def test_payload_is_kept_only_as_a_hash(path, key):
    payload = {"table": "employees", "columns": ["name", "salary"]}
    AuditLog(path, key).append(decision(payload_hash=payload_hash(payload)))
    text = path.read_text(encoding="utf-8")
    assert "salary" not in text and payload_hash(payload) in text


@pytest.mark.parametrize("kind,missing", [("quarantine", "reason_code"), ("release", "by"),
                                          ("revoke", "by"), ("restore", "agent")])
def test_a3_events_need_who_and_why(path, key, kind, missing):
    e = {"kind": kind, "agent": "research", "by": "kissa", "reason_code": "DENIAL_RATE_EXCEEDED"}
    AuditLog(path, key).append(e)
    del e[missing]
    with pytest.raises(ValueError):
        AuditLog(path, key).append(e)


def test_a3_events_are_chained_with_decisions(path, key):
    log = AuditLog(path, key)
    log.append(decision(decision="DENY", reason_code="ROLE_NOT_ALLOWED"))
    log.append({"kind": "quarantine", "agent": "research", "by": "broker",
                "reason_code": "DENIAL_RATE_EXCEEDED", "denials": [0, 1, 2, 3, 4]})
    log.append({"kind": "release", "agent": "research", "by": "kissa"})
    assert verify_chain(path, key.public_key()).ok
    assert [json.loads(x)["kind"] for x in lines(path)] == ["decision", "quarantine", "release"]


# --- tampering (A4 done-when) ---------------------------------------------------------

@pytest.mark.parametrize("n", [1, 3, 5])
def test_editing_one_line_fails_at_that_line(path, key, n):
    write_n(path, key)
    rows = lines(path)
    rows[n - 1] = rows[n - 1].replace('"ALLOW"', '"DENY"')
    put(path, rows)
    r = verify_chain(path, key.public_key())
    assert (r.ok, r.bad_line) == (False, n)
    assert "edited" in r.reason


def test_edit_with_recomputed_chain_is_caught_by_the_signature(path, key):
    """The attack Amna asked about: change a line and rebuild every hash after it."""
    write_n(path, key)
    recs = [json.loads(x) for x in lines(path)]
    recs[1]["decision"] = "DENY"
    prev = recs[0]["entry_hash"]
    for r in recs[1:]:
        r["prev_hash"] = prev
        r["entry_hash"] = audit.entry_hash_of(r)
        prev = r["entry_hash"]
    put(path, [canonical(r).decode() for r in recs])
    r = verify_chain(path, key.public_key())
    assert (r.ok, r.bad_line) == (False, 2)
    assert "signature" in r.reason


def test_whitespace_only_edit_is_caught(path, key):
    write_n(path, key, 2)
    rows = lines(path)
    rows[1] = rows[1].replace(",", ", ", 1)
    put(path, rows)
    assert verify_chain(path, key.public_key()).bad_line == 2


def test_deleted_line_is_caught(path, key):
    write_n(path, key)
    rows = lines(path)
    del rows[2]
    put(path, rows)
    assert verify_chain(path, key.public_key()).bad_line == 3


def test_swapped_lines_are_caught(path, key):
    write_n(path, key)
    rows = lines(path)
    rows[1], rows[2] = rows[2], rows[1]
    put(path, rows)
    assert verify_chain(path, key.public_key()).bad_line == 2


def test_inserted_line_from_another_log_is_caught(path, key, tmp_path):
    write_n(path, key)
    other = tmp_path / "other.jsonl"
    write_n(other, key, 1)
    rows = lines(path)
    rows.insert(2, lines(other)[0])
    put(path, rows)
    assert verify_chain(path, key.public_key()).bad_line == 3


def test_wrong_public_key_fails_at_line_one(path, key):
    write_n(path, key)
    r = verify_chain(path, Ed25519PrivateKey.generate().public_key())
    assert (r.ok, r.bad_line) == (False, 1)


def test_garbage_line_is_reported(path, key):
    write_n(path, key, 2)
    with open(path, "a", encoding="utf-8") as f:
        f.write("not json\n")
    r = verify_chain(path, key.public_key())
    assert (r.bad_line, r.reason) == (3, "not valid JSON")


def test_cannot_append_after_a_broken_last_line(path, key):
    write_n(path, key, 1)
    with open(path, "a", encoding="utf-8") as f:
        f.write("not json\n")
    with pytest.raises(ValueError):
        AuditLog(path, key)


def test_missing_or_empty_file_is_ok(path, key):
    assert verify_chain(path, key.public_key()).ok
    path.write_text("", encoding="utf-8")
    assert verify_chain(path, key.public_key()).lines == 0


# --- the command ------------------------------------------------------------------------

def keyfile(tmp_path, key):
    p = tmp_path / "k.pub"
    p.write_text(json.dumps(public_jwk(key.public_key())), encoding="utf-8")
    return p


def test_command_ok_and_fail(path, key, tmp_path, capsys):
    write_n(path, key)
    pub = keyfile(tmp_path, key)
    assert verify_main([str(path), "--public-key", str(pub)]) == 0
    assert "OK: 5 lines verified" in capsys.readouterr().out
    rows = lines(path)
    rows[3] = rows[3].replace("planner", "plannex")
    put(path, rows)
    assert verify_main([str(path), "--public-key", str(pub)]) == 1
    assert capsys.readouterr().out.startswith("FAIL: line 4:")


def test_python_dash_m_runs(path, key, tmp_path):
    write_n(path, key, 2)
    out = subprocess.run([sys.executable, "-m", "broker.audit.verify", str(path),
                          "--public-key", str(keyfile(tmp_path, key))],
                         capture_output=True, text=True, cwd=REPO)
    assert out.returncode == 0 and "OK: 2 lines verified" in out.stdout


# --- module-level append() (interface) and the key file --------------------------------------

def test_module_append_uses_the_configured_log(path, key):
    audit.configure(path, key)
    try:
        h = audit.append(decision())
    finally:
        audit.reset()
    assert json.loads(lines(path)[0])["entry_hash"] == h


def test_create_key_writes_a_pair_and_never_overwrites(tmp_path):
    priv, pub = tmp_path / "b.key", tmp_path / "b.pub"
    public = signing_key.create_key(priv, pub)
    assert signing_key.load_private_key(priv).public_key().public_bytes_raw() == public.public_bytes_raw()
    assert signing_key.load_public_key(pub).public_bytes_raw() == public.public_bytes_raw()
    if sys.platform != "win32":
        assert priv.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        signing_key.create_key(priv, pub)


def test_key_files_are_gitignored():
    out = subprocess.run(["git", "check-ignore", "keys/broker_signing.key", "keys/broker_signing.pub",
                          "logs/broker_audit.jsonl"], capture_output=True, text=True, cwd=REPO)
    assert out.stdout.split() == ["keys/broker_signing.key", "keys/broker_signing.pub",
                                  "logs/broker_audit.jsonl"]


# --- examples doc (A4 done-when) ----------------------------------------------------------------

def doc_blocks(lang):
    text = EXAMPLES_DOC.read_text(encoding="utf-8")
    return re.findall(rf"```{lang}\n(.*?)\n```", text, flags=re.S)


def test_examples_doc_has_every_decision_and_verifies(tmp_path):
    rows = doc_blocks("jsonl")
    recs = [json.loads(r) for r in rows]
    decisions = {r["decision"] for r in recs if r["kind"] == "decision"}
    assert decisions == {"ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE"}
    p = tmp_path / "examples.jsonl"
    put(p, rows)
    pub = public_key_from_jwk(json.loads(doc_blocks("json")[0]))
    r = verify_chain(p, pub)
    assert (r.ok, r.lines) == (True, len(example_entries()))


def test_examples_doc_matches_the_generator():
    recs = [json.loads(r) for r in doc_blocks("jsonl")]
    for rec, entry in zip(recs, example_entries(), strict=True):
        assert {k: rec[k] for k in entry} == json.loads(canonical(entry))
