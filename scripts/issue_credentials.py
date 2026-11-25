"""Issue one credential file per agent instance into keys/ (K1).

Writes 7 files (docs/identity-spec.md section 5): planner, research, database,
tool and mailer (instance <agent>-1), research-2 (a second research instance
with its own key) and research-stolen (a byte copy of research.json, for
stolen-credential scenarios). Each file holds the instance's private key, its
public JWK and a 60-minute token. keys/ is gitignored: never commit it.

Usage (from the repo root):
  & ".\\.venv\\Scripts\\python.exe" "scripts\\issue_credentials.py" [--force]
  & ".\\.venv\\Scripts\\python.exe" "scripts\\issue_credentials.py" --expired planner

--expired NAME prints an already expired token signed with NAME's key (A6)
and writes nothing. Keys and tokens are never printed otherwise.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity.keys import private_key_from_text, private_key_to_text, public_jwk
from broker.identity.tokens import issue_expired_token, issue_token
from contracts.catalog import get_catalog

DEFAULT_OUT = Path(__file__).resolve().parents[1] / "keys"
SECOND_INSTANCE_OF = "research"   # gets research-2.json
STOLEN_COPY_OF = "research"       # copied to research-stolen.json
FILE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def make_credential(agent: str, role: str, instance_id: str, epoch: int = 0) -> dict:
    """A new key and a token for one agent instance."""
    key = Ed25519PrivateKey.generate()
    return {
        "agent": agent,
        "role": role,
        "instance_id": instance_id,
        "epoch": epoch,
        "private_key": private_key_to_text(key),
        "public_jwk": public_jwk(key.public_key()),
        "token": issue_token(key, agent=agent, role=role, epoch=epoch),
    }


def credential_set() -> dict[str, dict]:
    """File name -> credential for all 7 files. Each catalog role is one agent of the same name."""
    creds = {role: make_credential(role, role, f"{role}-1") for role in get_catalog().roles}
    creds[f"{SECOND_INSTANCE_OF}-2"] = make_credential(
        SECOND_INSTANCE_OF, SECOND_INSTANCE_OF, f"{SECOND_INSTANCE_OF}-2")
    creds[f"{STOLEN_COPY_OF}-stolen"] = dict(creds[STOLEN_COPY_OF])
    return creds


def write_set(out_dir: Path, creds: dict[str, dict], force: bool) -> list[Path]:
    """Write every credential as <name>.json. Refuses to overwrite unless ``force``."""
    paths = [out_dir / f"{name}.json" for name in creds]
    existing = [p.name for p in paths if p.exists()]
    if existing and not force:
        raise FileExistsError(f"{', '.join(existing)} already exist; use --force to issue new keys")
    out_dir.mkdir(parents=True, exist_ok=True)
    for path, cred in zip(paths, creds.values()):
        path.write_text(json.dumps(cred, indent=2) + "\n", encoding="utf-8")
    return paths


def expired_token_for(out_dir: Path, name: str) -> str:
    """An expired token signed with the key in <name>.json."""
    if not FILE_NAME.match(name):
        raise ValueError(f"invalid credential name {name!r}")
    path = out_dir / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"{path.name} not found; issue credentials first")
    cred = json.loads(path.read_text(encoding="utf-8"))
    key = private_key_from_text(cred["private_key"])
    return issue_expired_token(key, agent=cred["agent"], role=cred["role"], epoch=cred["epoch"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output folder (default: keys/)")
    parser.add_argument("--force", action="store_true", help="replace existing credential files")
    parser.add_argument("--expired", metavar="NAME", help="print an expired token for NAME and exit")
    args = parser.parse_args(argv)

    try:
        if args.expired:
            print(expired_token_for(args.out, args.expired))
            return 0
        paths = write_set(args.out, credential_set(), args.force)
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {len(paths)} credential files to {args.out.name}/: "
          f"{', '.join(p.stem for p in paths)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
