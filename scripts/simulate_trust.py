"""Print T and the state for 30 messages from a good agent and from an attacker (A2).

Run from the repo root:
    python scripts/simulate_trust.py

Good agent: 30 ALLOW decisions on db.query_aggregate.
Attacker:   30 DENY decisions on db.query_rows (the A9 pattern, without A3's
            V1 quarantine, which is not part of the trust engine).
Uses the PROVISIONAL settings in broker/trust/trust_settings.yaml. No network.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.trust.risk import risk_vector  # noqa: E402
from broker.trust.trust import TrustEngine  # noqa: E402

MESSAGES = 30


def run() -> dict[str, list]:
    engine = TrustEngine()
    good = [engine.update("good", "ALLOW", risk_vector("db.query_aggregate"), False)
            for _ in range(MESSAGES)]
    bad = [engine.update("attacker", "DENY", risk_vector("db.query_rows"), False)
           for _ in range(MESSAGES)]
    return {"good": good, "attacker": bad}


def main() -> int:
    result = run()
    print(f"{'msg':>3}  {'good T':>7}  {'good state':<11}  {'attacker T':>10}  attacker state")
    for i, (g, b) in enumerate(zip(result["good"], result["attacker"]), 1):
        print(f"{i:>3}  {g.T:>7.4f}  {g.state:<11}  {b.T:>10.4f}  {b.state}")
    first_q = next((i for i, b in enumerate(result["attacker"], 1) if b.state == "Quarantined"), None)
    print()
    print(f"good agent always Active: {all(g.state == 'Active' for g in result['good'])}")
    print(f"attacker first Quarantined at message: {first_q}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
