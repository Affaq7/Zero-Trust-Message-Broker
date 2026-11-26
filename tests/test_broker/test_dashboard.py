"""F4: the read token on /api/state and /api/events, the dashboard page (served with a strict
CSP, no external URLs, textContent only), and data minimisation: no seeded sensitive value,
token or proof ever appears in the feeds or the page."""

import json
import re
import secrets

import httpx
import pytest
from fastapi.testclient import TestClient

from broker.app import DASHBOARD_CSP, STATIC_DIR, create_app
from broker.pipeline import TRUST_HISTORY_POINTS, Broker, Modules
from broker.policy.engine import PolicyResult
from contracts import Envelope, make_response, new_request
from contracts.payloads import ResponsePayload
from mocks.seed import payroll_rows, sensitive_values
from runner.evaluate import _appears

READ = "read-placeholder"
ADMIN = "admin-placeholder"
FEEDS = ["/api/state", "/api/events"]
PAGE_FILES = ["/dashboard", "/dashboard/dashboard.css", "/dashboard/dashboard.js"]


def n1(**over):
    fields = dict(sender="planner", receiver="database", action="db.query_aggregate",
                  resource="db:project_costs", payload={"metric": "sum", "column": "amount"},
                  chain_so_far=["user"])
    fields.update(over)
    return json.loads(new_request(**fields).model_dump_json())


def database(request):
    env = Envelope.model_validate_json(request.content)
    return httpx.Response(200, content=make_response(env, ResponsePayload(
        status="ok", result={"rows": [{"value": 1}]})).model_dump_json())


def app(environ, broker=None):
    broker = broker or Broker(Modules(), client=httpx.Client(transport=httpx.MockTransport(database)),
                              agent_urls={"database": "http://database.test"})
    return broker, TestClient(create_app(broker, environ=environ))


# --- the read token ----------------------------------------------------------------------------

@pytest.mark.parametrize("route", FEEDS)
def test_the_read_token_is_required(route):
    _, client = app({"BROKER_READ_TOKEN": READ})
    assert client.get(route, headers={"X-Read-Token": READ}).status_code == 200
    missing = client.get(route)
    wrong = client.get(route, headers={"X-Read-Token": "wrong-placeholder"})
    assert (missing.status_code, wrong.status_code) == (401, 401)
    assert READ not in missing.text + wrong.text and "wrong-placeholder" not in wrong.text


@pytest.mark.parametrize("route", FEEDS)
def test_an_unset_read_token_fails_closed_with_403(route):
    _, client = app({})
    assert client.get(route).status_code == 403
    assert client.get(route, headers={"X-Read-Token": ""}).status_code == 403
    assert client.get(route, headers={"X-Read-Token": "anything-placeholder"}).status_code == 403
    _, admin_only = app({"BROKER_ADMIN_TOKEN": ADMIN})                 # read token unset
    assert admin_only.get(route, headers={"X-Read-Token": "anything-placeholder"}).status_code == 403


@pytest.mark.parametrize("route", FEEDS)
def test_the_admin_token_is_accepted_on_the_read_routes(route):
    _, both = app({"BROKER_READ_TOKEN": READ, "BROKER_ADMIN_TOKEN": ADMIN})
    assert both.get(route, headers={"X-Admin-Token": ADMIN}).status_code == 200
    assert both.get(route, headers={"X-Admin-Token": "wrong-placeholder"}).status_code == 401
    _, admin_only = app({"BROKER_ADMIN_TOKEN": ADMIN})
    assert admin_only.get(route, headers={"X-Admin-Token": ADMIN}).status_code == 200


def test_the_read_token_is_not_accepted_on_admin_routes():
    _, client = app({"BROKER_READ_TOKEN": READ, "BROKER_ADMIN_TOKEN": ADMIN})
    r = client.post("/admin/revoke", json={"agent": "tool"}, headers={"X-Admin-Token": READ})
    assert r.status_code == 401


def test_read_refusals_are_not_added_to_the_event_list():
    broker, client = app({"BROKER_READ_TOKEN": READ})
    for _ in range(5):
        client.get("/api/state", headers={"X-Read-Token": "wrong-placeholder"})
    assert broker.recent_events(10) == []
    assert client.get("/health").json()["read"] == "enabled"


# --- the page ------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", PAGE_FILES)
def test_the_page_needs_no_token_and_has_a_strict_csp(path):
    _, client = app({})                                          # even with every token unset
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["content-security-policy"] == DASHBOARD_CSP
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    assert DASHBOARD_CSP.startswith("default-src 'none';") and "'unsafe-inline'" not in DASHBOARD_CSP
    assert "*" not in DASHBOARD_CSP and "http" not in DASHBOARD_CSP


def test_the_page_files_have_the_right_media_types():
    _, client = app({})
    types = {p: client.get(p).headers["content-type"].split(";")[0] for p in PAGE_FILES}
    assert types == {"/dashboard": "text/html", "/dashboard/dashboard.css": "text/css",
                     "/dashboard/dashboard.js": "text/javascript"}


def page_text() -> str:
    return "\n".join((STATIC_DIR / n).read_text(encoding="utf-8")
                     for n in ("dashboard.html", "dashboard.css", "dashboard.js"))


def test_the_page_has_no_external_urls():
    text = page_text()
    # The only absolute URL is the SVG namespace name, which createElementNS needs and which
    # is never fetched.
    urls = set(re.findall(r"(?:https?:)?//[\w.-]+\.[a-z]{2,}[^\s\"')]*", text))
    assert urls <= {"http://www.w3.org/2000/svg"}
    assert "@import" not in text and "url(" not in text and "@font-face" not in text
    html = (STATIC_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert re.findall(r'(?:src|href)="([^"]*)"', html) == ["/dashboard/dashboard.css", "/dashboard/dashboard.js"]


def test_the_page_never_writes_html_from_data_and_keeps_the_token_in_memory():
    js = (STATIC_DIR / "dashboard.js").read_text(encoding="utf-8")
    js = re.sub(r"^\s*//.*$", "", js, flags=re.M)                       # the code, not its comments
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                   "new Function", "localStorage", "sessionStorage", "document.cookie", "location.search",
                   "X-Admin-Token", "/admin/"):
        assert banned not in js, banned
    assert '"X-Read-Token": token' in js
    html = (STATIC_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert "style=" not in html and "<script>" not in html                 # no inline code or style
    assert not re.search(r"\son[a-z]+=", html)                             # no inline event handlers


def test_the_page_has_no_admin_controls():
    html = (STATIC_DIR / "dashboard.html").read_text(encoding="utf-8").lower()
    assert "approve" not in html and "reject" not in html and "release" not in html


# --- data minimisation ---------------------------------------------------------------------------

def leak_broker():
    """A broker that sees every kind of sensitive value: in request payloads, in a reply the
    content check cuts, in a request waiting for approval, in a malformed body, and in the
    Authorization and proof headers."""
    seeded = sensitive_values()
    rows = [{"employee_id": r[0], "salary": r[1], "bank_account": r[3]} for r in payroll_rows()]

    def receiver(request):
        env = Envelope.model_validate_json(request.content)
        return httpx.Response(200, content=make_response(env, ResponsePayload(
            status="ok", result={"rows": [{"value": 184250}, *rows]})).model_dump_json())

    def policy(env, identity):
        human = env.action == "tool.send_email_external"
        return PolicyResult(verdict="ALLOW", action_class="Conditional" if human else "Permitted",
                            reason_code="NEEDS_APPROVAL" if human else "POLICY_ALLOW", needs_human=human)

    modules = Modules.with_real(["content"])
    modules.evaluate_policy = policy
    broker = Broker(modules, client=httpx.Client(transport=httpx.MockTransport(receiver)),
                    agent_urls={"database": "http://database.test", "tool": "http://tool.test"})
    tokens = [secrets.token_urlsafe(48) for _ in range(4)]
    proofs = [secrets.token_urlsafe(48) for _ in range(4)]
    messages = [
        n1(),                                                                   # reply is cut
        n1(payload={"metric": "sum", "column": "amount", "note": seeded["ssn"][0]}),
        n1(action="db.query_rows", resource="db:payroll",
           payload={"table": "payroll", "columns": ["salary"], "where": {"bank_account": seeded["bank_account"][0]}}),
        n1(receiver="tool", action="tool.send_email_external", resource="mail:external",
           payload={"to": ["x@example.test"], "subject": "s", "body": seeded["home_address"][0]}),
    ]
    return broker, messages, tokens, proofs, seeded


def test_no_sensitive_value_token_or_proof_reaches_the_feeds_or_the_page():
    broker, messages, tokens, proofs, seeded = leak_broker()
    _, client = app({"BROKER_READ_TOKEN": READ, "BROKER_ADMIN_TOKEN": ADMIN}, broker)
    for msg, token, proof in zip(messages, tokens, proofs):
        client.post("/message", json=msg, headers={"Authorization": f"Bearer {token}", "X-Agent-Proof": proof})
    client.post("/message", content=("{bad " + seeded["ssn"][1]).encode(),
                headers={"Authorization": f"Bearer {tokens[0]}"})
    # The scenario really happened: a cut reply, a pending approval, a malformed body.
    state = client.get("/api/state", headers={"X-Read-Token": READ})
    events = client.get("/api/events?limit=1000", headers={"X-Read-Token": READ})
    s, e = state.json(), events.json()["events"]
    assert any(x.get("decision") == "SANITIZE" for x in e) and len(s["pending_approvals"]) == 1
    assert any(x.get("reason_code") == "MALFORMED_JSON" for x in e)

    pages = "".join(client.get(p).text for p in PAGE_FILES)
    for name, text in {"/api/state": state.text, "/api/events": events.text, "page": pages}.items():
        found = [v for values in seeded.values() for v in values if _appears(v, text)]
        assert found == [], f"seeded sensitive value(s) in {name}"
        assert not [t for t in tokens + proofs + [READ, ADMIN] if t in text], f"token or proof in {name}"
        assert "Bearer" not in text and '"payload"' not in text


# --- what the dashboard reads ----------------------------------------------------------------------

def test_state_has_role_revoked_counters_and_bounded_trust_history():
    def deny(env, identity):
        return PolicyResult(verdict="DENY", action_class="Permitted", reason_code="ROLE_NOT_ALLOWED",
                            needs_human=False)

    real_trust = Broker(Modules.with_real(["trust"]), client=httpx.Client(transport=httpx.MockTransport(database)),
                        agent_urls={"database": "http://database.test"})
    broker, client = app({"BROKER_READ_TOKEN": READ, "BROKER_ADMIN_TOKEN": ADMIN}, real_trust)
    client.headers.update({"X-Read-Token": READ, "X-Admin-Token": ADMIN})
    client.post("/message", json=n1())
    broker.modules.evaluate_policy = deny
    for _ in range(3):
        client.post("/message", json=n1())
    assert client.post("/admin/revoke", json={"agent": "tool"}).status_code == 200

    s = client.get("/api/state").json()
    agents = {a["agent"]: a for a in s["agents"]}
    assert agents["tool"]["revoked"] is True and agents["planner"]["revoked"] is False
    c = s["counters"]
    assert c["reason_codes"] == {"POLICY_ALLOW": 1, "ROLE_NOT_ALLOWED": 3}
    assert c["defence"] == {"quarantine": 0, "release": 0, "revoke": 1, "restore": 0}
    assert c["approvals"] == {"pending": 0, "approved": 0, "rejected": 0, "expired": 0}
    planner = s["trust_history"]["planner"]
    assert planner and all(len(p) == 3 for p in planner)            # [ts, T, state]
    assert planner[0][1] == 1.0 and planner[-1][1] < 1.0             # changes only, the drop recorded

    assert client.post("/admin/restore", json={"agent": "tool"}).status_code == 200
    assert {a["agent"]: a for a in client.get("/api/state").json()["agents"]}["tool"]["revoked"] is False


def test_trust_history_keeps_only_the_last_points():
    class Drifting:
        """A trust engine whose T moves on every update, so every message adds a point."""

        def __init__(self):
            self.n = 0

        def get(self, agent):
            from broker.stubs import TrustState
            return TrustState(agent=agent, T=1.0 - (self.n % 50) / 100, state="Active")

        def update(self, agent, *a, **kw):
            self.n += 1
            return self.get(agent)

    broker, _ = app({}, Broker(Modules(trust=Drifting()), client=httpx.Client(transport=httpx.MockTransport(database)),
                               agent_urls={"database": "http://database.test"}))
    for _ in range(TRUST_HISTORY_POINTS + 50):
        broker.handle(n1(), {})
    assert len(broker.state()["trust_history"]["planner"]) == TRUST_HISTORY_POINTS == 200
