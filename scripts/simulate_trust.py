"""Trust engine simulation (A2) and the calibration sweep (A-R1).

Run from the repo root:
    python scripts/simulate_trust.py
        30 messages from a good agent and from an attacker, with the settings
        in broker/trust/trust_settings.yaml (A2).
    python scripts/simulate_trust.py --sweep [--events results/<run_id>/events.jsonl ...]
        the A-R1 grid (lambda x eta) for a normal, a noisy and an attacker
        agent; prints a markdown table and writes figures/trust_*.svg.

Good agent: 30 ALLOW decisions on db.query_aggregate.
Attacker:   30 DENY decisions on db.query_rows (the A9 pattern, without A3's
            V1 quarantine, which is not part of the trust engine).
Normal (sweep): the real request sequence of every agent in N1 to N4 runs
            (events.jsonl, direct mode, fake model), each request decided as
            the broker would decide it for an honest agent: ALLOW, or HITL for
            tool.send_email_external. Without --events, 60 ALLOW plus one HITL.
Noisy (sweep): 60 ALLOW on db.query_aggregate with one DENY every 10 messages.
No network.
"""

import argparse
import copy
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from broker.trust.risk import risk_vector  # noqa: E402
from broker.trust.trust import TrustEngine, default_settings  # noqa: E402

MESSAGES = 30
LAMBDAS = (0.2, 0.5, 1.0)
ETAS = (0.05, 0.1)
NOISY_MESSAGES = 60
NOISY_EVERY = 10
ATTACKER_MESSAGES = 30
FIGURES = REPO / "figures"


def run() -> dict[str, list]:
    engine = TrustEngine()
    good = [engine.update("good", "ALLOW", risk_vector("db.query_aggregate"), False)
            for _ in range(MESSAGES)]
    bad = [engine.update("attacker", "DENY", risk_vector("db.query_rows"), False)
           for _ in range(MESSAGES)]
    return {"good": good, "attacker": bad}


# --- A-R1 sweep ------------------------------------------------------------------

def honest_decision(action: str) -> str:
    """What the broker decides for an honest agent's request (policy step 4)."""
    return "HITL" if action == "tool.send_email_external" else "ALLOW"


def load_normal(paths: list[Path]) -> dict[str, list[tuple[str, str]]]:
    """Per sender, its requests in order across all runs: [(action, decision)]."""
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            rows += [json.loads(line) for line in f if line.strip()]
    reqs = [r for r in rows if r.get("direction") == "in" and r.get("msg_type") == "request"]
    reqs.sort(key=lambda r: (r.get("run_id", ""), r["logged_at"]))
    out: dict[str, list] = defaultdict(list)
    for r in reqs:
        out[r["sender"]].append((r["action"], honest_decision(r["action"])))
    return dict(out)


def synthetic_normal() -> dict[str, list[tuple[str, str]]]:
    seq = [("db.query_aggregate", "ALLOW")] * 30 + [("tool.send_email_external", "HITL")] \
        + [("db.query_aggregate", "ALLOW")] * 30
    return {"planner": seq}


def noisy_sequence() -> list[tuple[str, str]]:
    return [("db.query_aggregate", "DENY" if i % NOISY_EVERY == 0 else "ALLOW")
            for i in range(1, NOISY_MESSAGES + 1)]


def attacker_sequence() -> list[tuple[str, str]]:
    return [("db.query_rows", "DENY")] * ATTACKER_MESSAGES


def settings_for(lam: float, eta: float, base: dict | None = None) -> dict:
    s = copy.deepcopy(base or default_settings())
    s["lambda"], s["eta"] = lam, eta
    return s


def trace(settings: dict, seq: list[tuple[str, str]], agent: str = "a") -> list:
    e = TrustEngine(settings)
    return [e.update(agent, d, risk_vector(a), False) for a, d in seq]


def first(states: list, name: str) -> int | None:
    return next((i for i, s in enumerate(states, 1) if s.state == name), None)


def evaluate(lam: float, eta: float, normal: dict, base: dict | None = None) -> dict:
    s = settings_for(lam, eta, base)
    norm = [st for seq in normal.values() for st in trace(s, seq)]
    noisy = trace(s, noisy_sequence())
    att = trace(s, attacker_sequence())
    outside = [st.state != "Active" for st in noisy]
    longest, run_ = 0, 0
    for o in outside:
        run_ = run_ + 1 if o else 0
        longest = max(longest, run_)
    return {
        "lambda": lam, "eta": eta,
        "normal_min_T": min(st.T for st in norm),
        "normal_always_active": all(st.state == "Active" for st in norm),
        "noisy_min_T": min(st.T for st in noisy),
        "noisy_msgs_outside_active": sum(outside),
        "noisy_longest_outside": longest,
        "attacker_suspicious_at": first(att, "Suspicious"),
        "attacker_restricted_at": first(att, "Restricted"),
        "attacker_quarantined_at": first(att, "Quarantined"),
        "traces": {"noisy": [st.T for st in noisy], "attacker": [st.T for st in att]},
    }


def passes(r: dict) -> bool:
    """A-R1 rule (Amna, 25 Nov): normal agents never leave Active, and the
    attacker is Restricted within 5 messages (V1 in A3 quarantines it at 5)."""
    return r["normal_always_active"] and (r["attacker_restricted_at"] or 99) <= 5


def choose(results: list[dict]) -> dict | None:
    """Among passing values, the noisy agent spends the fewest messages outside
    Active; then the attacker drops fastest; then the larger lambda."""
    ok = [r for r in results if passes(r)]
    if not ok:
        return None
    return min(ok, key=lambda r: (r["noisy_msgs_outside_active"], r["noisy_longest_outside"],
                                  r["attacker_restricted_at"], r["attacker_suspicious_at"],
                                  -r["lambda"], r["eta"]))


def sweep(normal: dict, base: dict | None = None) -> list[dict]:
    return [evaluate(lam, eta, normal, base) for lam in LAMBDAS for eta in ETAS]


def table(results: list[dict], chosen: dict | None) -> str:
    head = ("| lambda | eta | normal lowest T | normal always Active | noisy lowest T | "
            "noisy msgs outside Active | noisy longest stretch | attacker Suspicious at | "
            "attacker Restricted at | attacker Quarantined at | passes |")
    lines = [head, "|" + "---|" * 11]
    for r in results:
        mark = " (chosen)" if r is chosen else ""
        lines.append(
            f"| {r['lambda']} | {r['eta']}{mark} | {r['normal_min_T']:.4f} | "
            f"{'yes' if r['normal_always_active'] else 'no'} | {r['noisy_min_T']:.4f} | "
            f"{r['noisy_msgs_outside_active']} | {r['noisy_longest_outside']} | "
            f"{r['attacker_suspicious_at']} | {r['attacker_restricted_at']} | "
            f"{r['attacker_quarantined_at']} | {'yes' if passes(r) else 'no'} |")
    return "\n".join(lines)


# --- SVG plots (no plotting library) ------------------------------------------------

COLORS = ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2"]


def svg_lines(series: list[tuple[str, list[float]]], title: str, bands: dict) -> str:
    W, H, L, R, T, B = 900, 400, 56, 300, 36, 44
    n = max(len(v) for _, v in series)
    x = lambda i: L + (W - L - R) * (i / max(n - 1, 1))  # noqa: E731
    y = lambda t: T + (H - T - B) * (1 - t)               # noqa: E731
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           'font-family="sans-serif" font-size="12">',
           f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
           f'<text x="{L}" y="22" font-size="14" font-weight="bold">{title}</text>']
    for name, edge in (("Active", bands["active"]), ("Suspicious", bands["suspicious"]),
                       ("Restricted", bands["restricted"])):
        out.append(f'<line x1="{L}" y1="{y(edge):.1f}" x2="{W - R}" y2="{y(edge):.1f}" '
                   'stroke="#9ca3af" stroke-dasharray="4 4"/>')
        out.append(f'<text x="{W - R + 4}" y="{y(edge) + 4:.1f}" fill="#6b7280">{name} {edge}</text>')
    for t in (0, 0.2, 0.4, 0.6, 0.8, 1.0):
        out.append(f'<text x="{L - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{t:.1f}</text>')
    for i in range(0, n, 5 if n <= 30 else 10):
        out.append(f'<text x="{x(i):.1f}" y="{H - B + 16}" text-anchor="middle">{i + 1}</text>')
    out.append(f'<text x="{(L + W - R) / 2:.0f}" y="{H - 8}" text-anchor="middle">message</text>')
    out.append(f'<text x="14" y="{(T + H - B) / 2:.0f}" transform="rotate(-90 14 {(T + H - B) / 2:.0f})" '
               'text-anchor="middle">trust score T</text>')
    out.append(f'<rect x="{L}" y="{T}" width="{W - L - R}" height="{H - T - B}" fill="none" stroke="#374151"/>')
    for k, (name, vals) in enumerate(series):
        c = COLORS[k % len(COLORS)]
        pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(vals))
        out.append(f'<polyline points="{pts}" fill="none" stroke="{c}" stroke-width="2"/>')
        ly = T + 16 + 18 * k
        out.append(f'<line x1="{W - R + 110}" y1="{ly}" x2="{W - R + 130}" y2="{ly}" stroke="{c}" stroke-width="2"/>')
        out.append(f'<text x="{W - R + 134}" y="{ly + 4}">{name}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def write_figures(results: list[dict], bands: dict, eta: float) -> list[Path]:
    FIGURES.mkdir(exist_ok=True)
    att = [(f"lambda {r['lambda']}", r["traces"]["attacker"]) for r in results if r["eta"] == eta]
    noisy = [(f"lambda {r['lambda']}, eta {r['eta']}", r["traces"]["noisy"]) for r in results]
    files = {
        "trust_attacker.svg": svg_lines(att, f"Attacker (all DENY), eta {eta}: T by message", bands),
        "trust_noisy.svg": svg_lines(noisy, "Noisy agent (one DENY every 10 messages): T by message", bands),
    }
    paths = []
    for name, text in files.items():
        (FIGURES / name).write_text(text, encoding="utf-8")
        paths.append(FIGURES / name)
    return paths


def main_sweep(events: list[Path], write: bool) -> int:
    normal = load_normal(events) if events else synthetic_normal()
    results = sweep(normal)
    chosen = choose(results)
    msgs = sum(len(v) for v in normal.values())
    print(f"normal data: {'events.jsonl x ' + str(len(events)) if events else 'synthetic'}, "
          f"{msgs} requests from {', '.join(sorted(normal))}")
    print()
    print(table(results, chosen))
    print()
    print(f"chosen: lambda {chosen['lambda']}, eta {chosen['eta']}" if chosen else "chosen: none passes")
    if write and chosen:
        for p in write_figures(results, default_settings()["bands"], chosen["eta"]):
            print(f"wrote {p.relative_to(REPO)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--sweep", action="store_true", help="run the A-R1 lambda x eta grid")
    p.add_argument("--events", type=Path, nargs="*", default=[], help="events.jsonl files (normal data)")
    p.add_argument("--no-figures", action="store_true", help="do not write figures/trust_*.svg")
    args = p.parse_args(argv)
    if args.sweep:
        return main_sweep(args.events, not args.no_figures)
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
