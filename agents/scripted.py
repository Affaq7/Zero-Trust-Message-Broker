"""Scripted attack agent — a standalone script, NOT a uvicorn wrapper.

Reads a config JSON (written by the runner), sends each step as a raw HTTP
request to the victim agent's wrapper, and logs every exchange to
script_log.jsonl.

In broker mode (config "mode": "broker") every request goes to the broker with
the sender's ISSUED credentials (the run's keys folder, never keys/) and a
per-message proof, as a compromised agent holding real credentials would send
it; token modes valid / expired / stolen / reissued / missing shape the
identity attack. A step with bypass_broker goes straight to the receiver's own
port (A12). The admin token is never given to this process.  The agent never modifies a payload, never generates text,
and never judges success; every byte comes from the scenario JSON.  Evaluation
is the runner's job after this process exits.

Usage:  python -m agents.scripted --config <path-to-script_config.json>
"""

import argparse
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from contracts.version import SCHEMA_VERSION
from wrapper.credentials import make_expired_token, make_stub_token, make_wrong_key_token

MAX_STEPS = 50
SEND_TIMEOUT = 30
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
_LOOPBACK_ADDRESSES = frozenset(
    {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")})
REQUIRED_STEP_KEYS = ("receiver", "action", "resource")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_loopback(url: str) -> bool:
    """True only if the host is loopback. A name is resolved and EVERY address it gives must be
    127.0.0.1 or ::1; a name that cannot be resolved is not loopback."""
    host = urlparse(url).hostname or ""
    if host in LOOPBACK:
        return True
    try:
        addresses = {info[4][0].split("%")[0] for info in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError):
        return False
    if not addresses:
        return False
    try:
        return all(ipaddress.ip_address(a) in _LOOPBACK_ADDRESSES for a in addresses)
    except ValueError:
        return False


def _append_jsonl(path: Path, record: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _broker_auth(step: dict, envelope: dict, sender: str, keys_dir: Path) -> dict[str, str]:
    """Authorization and X-Agent-Proof headers for one request through the broker.

    valid     the sender's issued token, proof signed with the sender's own key
    expired   a token for the sender that expired an hour ago, proof with its key (A6)
    stolen    research-stolen.json's token, proof signed with a fresh key (A14)
    reissued  a new token with epoch token_epoch, signed with the sender's key (A10)
    missing   neither header
    """
    from broker.identity.client import make_proof
    from broker.identity.keys import private_key_from_text
    from broker.identity.tokens import issue_expired_token, issue_token
    from contracts.envelope import Envelope

    mode = step.get("token", "valid")
    if mode == "missing":
        return {}
    name = f"{STOLEN_FROM}-stolen" if mode == "stolen" else sender
    cred = json.loads((keys_dir / f"{name}.json").read_text(encoding="utf-8"))
    key = private_key_from_text(cred["private_key"])
    if mode == "valid" or mode == "stolen":
        token = cred["token"]
    elif mode == "expired":
        token = issue_expired_token(key, agent=cred["agent"], role=cred["role"], epoch=cred["epoch"])
    elif mode == "reissued":
        token = issue_token(key, agent=cred["agent"], role=cred["role"], epoch=int(step["token_epoch"]))
    else:
        raise ValueError(f"token mode {mode!r} is not used in broker mode")
    proof_key = Ed25519PrivateKey.generate() if mode == "stolen" else key   # the thief has no key
    headers = {"Authorization": f"Bearer {token}"}
    try:
        headers["X-Agent-Proof"] = make_proof(Envelope.model_validate(envelope), token, proof_key)
    except ValueError:
        pass                                     # a deliberately malformed envelope gets no proof
    return headers


STOLEN_FROM = "research"         # scripts/issue_credentials.py copies research.json to research-stolen.json


def _build_token(mode: str, sender: str, role: str, receiver: str,
                 key: Ed25519PrivateKey) -> str | None:
    if mode == "valid":
        return make_stub_token(sender, role, receiver, key=key)
    if mode == "expired":
        return make_expired_token(sender, role, receiver, key=key)
    if mode == "wrong_key":
        return make_wrong_key_token(sender, role, receiver)
    return None  # "missing"


def run(config_path: str) -> int:
    cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
    agent_urls: dict[str, str] = cfg["agent_urls"]
    default_sender: str = cfg["sender"]
    default_role: str = cfg["sender_role"]
    steps: list[dict] = cfg["steps"]
    log_path = Path(cfg["log_path"])
    trace_id: str = cfg.get("trace_id", str(uuid4()))
    max_steps: int = min(cfg.get("max_steps", MAX_STEPS), MAX_STEPS)   # the config can lower the cap, never raise it
    broker_mode = cfg.get("mode", "direct") == "broker"
    broker_url: str | None = cfg.get("broker_url")
    keys_dir = Path(cfg["keys_dir"]) if cfg.get("keys_dir") else None
    first_step: int = int(cfg.get("first_step", 0))      # the runner splits steps around admin calls
    append: bool = bool(cfg.get("append", False))
    if broker_mode and (not broker_url or keys_dir is None):
        print("ABORT: broker mode needs broker_url and keys_dir", file=sys.stderr)
        return 1

    if len(steps) > max_steps:
        print(f"ABORT: {len(steps)} steps exceed cap of {max_steps}", file=sys.stderr)
        return 1

    for name, url in [*agent_urls.items(), *([("broker", broker_url)] if broker_mode else [])]:
        if not _is_loopback(url):
            print(f"ABORT: {name} URL {url} is not loopback", file=sys.stderr)
            return 1

    # Every step is checked before the first request, so a bad one aborts the run with nothing sent.
    for i, step in enumerate(steps):
        missing = [k for k in REQUIRED_STEP_KEYS if not step.get(k)]
        if missing:
            print(f"ABORT: step {i} lacks {missing}", file=sys.stderr)
            return 1
        if step["receiver"] not in agent_urls:
            print(f"ABORT: step {i} receiver {step['receiver']!r} has no URL", file=sys.stderr)
            return 1

    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not append:
        log_path.write_text("", encoding="utf-8")      # a fresh log, never appended to an old one
    creds_key = Ed25519PrivateKey.generate()

    ok_count = 0
    err_count = 0

    for n, step in enumerate(steps):
        i = first_step + n
        sender = step.get("sender") or default_sender
        role = step.get("sender_role") or default_role
        receiver = step["receiver"]
        via_broker = broker_mode and not step.get("bypass_broker", False)
        receiver_url = broker_url if via_broker else agent_urls[receiver]

        envelope: dict = {
            "schema_version": SCHEMA_VERSION,
            "msg_id": str(uuid4()),
            "trace_id": trace_id,
            "parent_msg_id": None,
            "msg_type": step.get("msg_type", "request"),
            "sender": sender,
            "receiver": receiver,
            "action": step["action"],
            "resource": step["resource"],
            "payload": step.get("payload", {}),
            "delegation_chain": step.get("delegation_chain") or ["user", sender],
            "timestamp": _utc_iso(),
        }
        for k, v in step.get("extra_fields", {}).items():
            envelope[k] = v

        token_mode = step.get("token", "valid")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if broker_mode:
            headers.update(_broker_auth(step, envelope, sender, keys_dir))
        else:
            token = _build_token(token_mode, sender, role, receiver, creds_key)
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"

        t0 = time.monotonic()
        try:
            resp = httpx.post(
                f"{receiver_url}/message",
                content=json.dumps(envelope, ensure_ascii=False),
                headers=headers,
                timeout=SEND_TIMEOUT,
                trust_env=False,        # never use proxy environment variables
            )
            status_code = resp.status_code
            try:
                body = resp.json()
            except Exception:
                body = resp.text
        except Exception as exc:
            status_code = 0
            body = str(exc)
        elapsed_ms = round((time.monotonic() - t0) * 1000)

        if 200 <= status_code < 300:
            ok_count += 1
        else:
            err_count += 1

        _append_jsonl(log_path, {
            "step": i,
            "envelope": envelope,
            "token_mode": token_mode,
            "via": "broker" if via_broker else "direct",
            "http_status": status_code,
            "response_body": body,
            "elapsed_ms": elapsed_ms,
            "logged_at": _utc_iso(),
        })

        pause_ms = step.get("pause_ms", 0)
        if pause_ms > 0:
            time.sleep(pause_ms / 1000)

    _append_jsonl(log_path, {
        "summary": True,
        "steps_total": len(steps),
        "steps_ok": ok_count,
        "steps_error": err_count,
        "finished_at": _utc_iso(),
    })
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="python -m agents.scripted")
    p.add_argument("--config", required=True, help="path to script_config.json")
    args = p.parse_args()
    sys.exit(run(args.config))


if __name__ == "__main__":
    main()
