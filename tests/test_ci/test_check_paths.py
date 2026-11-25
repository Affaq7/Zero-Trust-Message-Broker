"""Unit tests for scripts/ci/check_paths.py against the real .github/ownership.json."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "ci"))

import check_paths as cp  # noqa: E402

CONFIG = cp.load_config()
CONTRACTS, PROMPTS, CROSS = "contracts-approved", "prompt-change-approved", "cross-owner-approved"


def run(branch, files, labels=(), hash_lines=False):
    return cp.evaluate(CONFIG, list(files), branch, set(labels), hash_lines)


def test_labels_in_config():
    assert CONFIG["labels"] == {"contracts": CONTRACTS, "frozen_prompts": PROMPTS, "cross_owner": CROSS}


def test_frozen_prompt_modules_exist():
    for f in CONFIG["frozen_prompts"]["files"] + [CONFIG["frozen_prompts"]["hash_records"]["file"]]:
        assert (REPO_ROOT / f).is_file(), f
    doc = (REPO_ROOT / CONFIG["frozen_prompts"]["hash_records"]["file"]).read_text(encoding="utf-8")
    for marker in CONFIG["frozen_prompts"]["hash_records"]["markers"]:
        assert marker in doc, marker


# (a) contracts
@pytest.mark.parametrize("branch", ["afaq/x", "kissa/x", "amna/x", "feature/x"])
def test_contracts_need_their_label_on_every_branch(branch):
    res = run(branch, ["contracts/catalog.py"])
    assert any(e.startswith("contracts-change: contracts/catalog.py") for e in res.errors)
    ok = run(branch, ["contracts/catalog.py"], [CONTRACTS])
    assert ok.errors == []  # the contracts label alone is enough; no cross-owner label needed


# (b) frozen prompts
@pytest.mark.parametrize("path", ["agents/planner.py", "agents/research.py"])
def test_frozen_prompt_modules_need_the_prompt_label(path):
    assert run("afaq/x", [path]).errors == [f"frozen-prompt-change: {path} needs label {PROMPTS}"]
    assert run("afaq/x", [path], [PROMPTS]).errors == []
    assert run("afaq/x", [path], [CONTRACTS, CROSS]).errors  # other labels do not count


def test_hash_record_lines_need_the_prompt_label():
    res = run("afaq/x", ["docs/measurements.md"], hash_lines=True)
    assert len(res.errors) == 1 and "frozen prompt hash line" in res.errors[0]
    assert run("afaq/x", ["docs/measurements.md"], [PROMPTS], hash_lines=True).errors == []
    assert run("afaq/x", ["docs/measurements.md"]).errors == []  # other lines of the doc are fine


def test_hash_record_touched_by_marker():
    markers = CONFIG["frozen_prompts"]["hash_records"]["markers"]
    assert cp.hash_record_touched(CONFIG, [(114, f"{markers[1]}: `{'0' * 64}`")])
    assert not cp.hash_record_touched(CONFIG, [(5, "| 2026-11-01 | some timing row |")])


# (c) ownership
def test_kissa_owns_identity_and_policy():
    files = ["broker/identity/keys.py", "broker/policy/rbac.py", "broker/intercept/hook.py",
             "scripts/issue_credentials.py", "wrapper/credentials.py",
             "tests/test_broker/test_registry.py", "tests/test_broker/test_identity_tokens.py",
             "tests/test_broker/test_policy.py", "tests/test_broker/test_validate_envelope.py",
             "docs/identity-spec.md", "docs/scenario-control-map.md", "docs/open-questions.md"]
    res = run("kissa/identity-policy", files)
    assert res.errors == [] and res.warnings == []


def test_amna_owns_trust_and_defence():
    files = ["broker/trust/score.py", "broker/defence/rules.py", "broker/audit/log.py",
             "broker/transport/http.py", "scripts/simulate_trust.py",
             "tests/test_broker/test_risk.py", "tests/test_broker/test_trust_decay.py",
             "tests/test_broker/test_defence.py", "tests/test_broker/test_audit.py",
             "tests/test_broker/test_signing.py", "docs/trust-calibration.md",
             "docs/detection-design.md", "docs/audit-log-examples.md", "docs/open-questions.md"]
    assert run("amna/trust", files).errors == []


@pytest.mark.parametrize("branch, path", [
    ("kissa/x", "broker/trust/score.py"), ("kissa/x", "tests/test_broker/test_signing.py"),
    ("kissa/x", "wrapper/runtime.py"), ("kissa/x", "pyproject.toml"), ("kissa/x", "broker/__init__.py"),
    ("amna/x", "broker/identity/keys.py"), ("amna/x", "tests/test_broker/test_registry.py"),
    ("amna/x", "docs/identity-spec.md"), ("amna/x", "runner/run.py"),
])
def test_cross_owner_edits_need_the_label(branch, path):
    res = run(branch, [path])
    assert res.errors == [f"cross-owner-change: {path} is outside {branch.split('/')[0]}/* ownership; "
                          f"needs label {CROSS}"]
    assert run(branch, [path], [CROSS]).errors == []


def test_folder_patterns_do_not_match_lookalike_folders():
    assert run("kissa/x", ["broker/identityx/a.py"]).errors
    assert cp.matches("broker/identity/a.py", "broker/identity/")
    assert not cp.matches("broker/identity", "broker/identity/")


def test_afaq_may_touch_anything_except_contracts_and_prompts():
    files = ["runner/run.py", "broker/identity/keys.py", "broker/trust/score.py", ".github/ownership.json"]
    assert run("afaq/ci-safety-checks", files).errors == []
    res = run("afaq/x", files + ["contracts/envelope.py", "agents/planner.py"])
    assert len(res.errors) == 2


def test_unknown_prefix_only_warns_but_contracts_still_fail():
    res = run("feature/x", ["runner/run.py", "broker/trust/x.py"])
    assert res.errors == [] and len(res.warnings) == 1
    assert run("main", ["contracts/version.py"]).errors


def test_owner_prefix_needs_the_slash():
    assert cp.owner_prefix("kissa/x", CONFIG["owners"]) == "kissa/"
    assert cp.owner_prefix("kissa-x", CONFIG["owners"]) is None
    assert cp.owner_prefix("afaqx/y", CONFIG["owners"]) is None


def test_labels_and_branch_come_from_the_event_payload():
    event = {"pull_request": {"head": {"ref": "amna/trust", "sha": "h"}, "base": {"sha": "b"},
                              "labels": [{"name": CROSS}, {"name": "docs"}]}}
    branch, labels = cp.pr_context(event, None, None)
    assert branch == "amna/trust" and labels == {CROSS, "docs"}
    assert cp.pr_context(event, "kissa/y", ["x"]) == ("kissa/y", {"x"})
