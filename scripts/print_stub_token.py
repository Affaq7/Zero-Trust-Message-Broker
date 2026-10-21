"""Print a STUB JWT for manual tests. Direct mode never checks it.

STUB: real credentials come from a teammate's issuing script. This token is
signed with a throwaway Ed25519 key that exists only in memory and is
discarded when the script exits, so nobody can ever verify it. Nothing is
written to disk. The signing code lives in wrapper/credentials.py.

Usage (from the repo root):
  & ".\\.venv\\Scripts\\python.exe" "scripts\\print_stub_token.py" [--sub planner] [--role planner] [--aud dummy]
"""

import argparse
import sys

from pydantic import ValidationError

from wrapper.credentials import make_stub_token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print a STUB JWT (unverifiable).")
    parser.add_argument("--sub", default="planner", help="must equal the envelope sender")
    parser.add_argument("--role", default="planner")
    parser.add_argument("--aud", default="dummy", help="receiver agent in direct mode")
    args = parser.parse_args(argv)
    try:
        print(make_stub_token(args.sub, args.role, args.aud))
    except ValidationError as exc:
        print(f"invalid claims: {exc.errors(include_url=False)[0]['msg']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
