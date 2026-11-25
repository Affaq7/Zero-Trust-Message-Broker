"""Risk module (task A1, Amna). Pipeline step 6, before the trust score.

Rates each catalog action on seven factors (R, T, D, E, P, A, S; L/M/H) and
says how much trust an action needs. Ratings, the approved scale and the
thresholds are data, in risk_ratings.yaml next to this file. They are
PROVISIONAL (docs/open-questions.md S16); thresholds are calibrated in A-R1.

Pure Python: no network, no model calls, same answer for the same input.
Interfaces fixed on 25 Nov (context file, section 7):
    risk_vector(action) -> dict[str, str]
    required_trust(action_class, risk) -> float
Extra helpers: is_compound_high(action) (a flag only), is_critical(action)
(the individual_data field, for the trust engine, A2).
"""

from functools import lru_cache
from pathlib import Path

import yaml

from contracts.catalog import get_catalog

RATINGS_PATH = Path(__file__).with_name("risk_ratings.yaml")

FACTORS = ("R", "T", "D", "E", "P", "A", "S")
LEVELS = ("L", "M", "H")
THRESHOLD_KEYS = ("Permitted", "Conditional", "deny_below")

# Returned by required_trust when no trust score is enough (Prohibited or
# unknown class). Any T in [0, 1] is below it, so the answer is never ALLOW.
NEVER = float("inf")

# Default-deny: an action the catalog does not know gets the worst rating.
_UNKNOWN = ({f: "H" for f in FACTORS}, True)


def _check_vector(name: str, vec: object) -> dict[str, str]:
    if not isinstance(vec, dict) or set(vec) != set(FACTORS):
        raise ValueError(f"{name}: needs exactly the factors {FACTORS}, got {vec!r}")
    for factor, level in vec.items():
        if level not in LEVELS:
            raise ValueError(f"{name}: factor {factor} has {level!r}, expected one of {LEVELS}")
    return {f: vec[f] for f in FACTORS}


def _check_entry(name: str, entry: object) -> tuple[dict[str, str], bool]:
    if not isinstance(entry, dict) or "individual_data" not in entry:
        raise ValueError(f"{name}: needs the seven factors and individual_data")
    entry = dict(entry)
    individual = entry.pop("individual_data")
    if not isinstance(individual, bool):
        raise ValueError(f"{name}: individual_data must be true or false, got {individual!r}")
    return _check_vector(name, entry), individual


def load_ratings(path: Path = RATINGS_PATH) -> tuple[dict[str, tuple[dict[str, str], bool]], dict[str, float]]:
    """Load and check the ratings file against the action catalog.

    Returns ({action: (vector, individual_data)}, thresholds). Fails if any
    catalog action is unrated, if the file rates an action the catalog does
    not have, or if a value is not valid.
    """
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    ratings = {name: _check_entry(name, entry) for name, entry in raw["ratings"].items()}
    catalog_names = get_catalog().names()
    missing = catalog_names - set(ratings)
    extra = set(ratings) - catalog_names
    if missing or extra:
        raise ValueError(f"ratings do not match the catalog: missing {sorted(missing)}, extra {sorted(extra)}")

    thresholds = {k: float(v) for k, v in raw["thresholds"].items()}
    if set(thresholds) != set(THRESHOLD_KEYS):
        raise ValueError(f"thresholds need exactly {sorted(THRESHOLD_KEYS)}, got {sorted(thresholds)}")
    for k, v in thresholds.items():
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"threshold {k} = {v} is outside 0..1")
    return ratings, thresholds


@lru_cache(maxsize=1)
def _data():
    return load_ratings()


def thresholds() -> dict[str, float]:
    """The current thresholds (a copy)."""
    return dict(_data()[1])


def _entry(action: str) -> tuple[dict[str, str], bool]:
    return _data()[0].get(action, _UNKNOWN)


def risk_vector(action: str) -> dict[str, str]:
    """Seven-factor vector for an action, keys R,T,D,E,P,A,S, values L/M/H.

    An action that is not in the catalog gets all H (default-deny). The policy
    step should already have denied it.
    """
    return dict(_entry(action)[0])


def is_compound_high(action: str) -> bool:
    """True when two or more factors are High. A flag only, for the audit log."""
    return sum(1 for level in risk_vector(action).values() if level == "H") >= 2


def is_critical(action: str) -> bool:
    """True when the action returns individual-level personal data
    (individual_data in the ratings file). Unknown actions count as critical.
    For the trust engine (A2) only."""
    return _entry(action)[1]


def required_trust(action_class: str, risk: dict) -> float:
    """Minimum trust score T an agent needs for ALLOW.

    Permitted needs the Permitted threshold (0.80 to start), Conditional the
    Conditional one (0.60). Never below deny_below (0.40). Prohibited, Unknown
    or any other class returns NEVER. The risk vector is checked but does not
    change the result for now: compound high is a flag only (Amna, 25 Nov).
    """
    _check_vector("risk", risk)
    t = thresholds()
    if action_class not in ("Permitted", "Conditional"):
        return NEVER
    return max(t[action_class], t["deny_below"])
