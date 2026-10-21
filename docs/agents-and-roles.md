# Agents and roles

Generated from `contracts/action_catalog.yaml` (v0.2, with the provisional
Q11 caller changes) and `wrapper/registry.py` on 2026-10-22. The catalog
is enforced by the broker only; direct mode ignores it.

| Agent | Role | Actions it may call | Actions it serves | Built and registered? |
|---|---|---|---|---|
| planner | planner | `db.query_aggregate`, `db.query_rows`, `db.update_records`, `file.read_internal`, `file.delete`, `tool.send_email_internal`, `tool.send_email_external` | none (no action has `served_by: planner`; gap G2) | yes: message handler (replies with an error) and task handler (`POST /task`, the entry point) |
| research | research | `db.query_aggregate`, `file.read_internal`, `web.fetch_page` | none (gap G1) | no: waits for G1 |
| database | database | none | `db.query_aggregate`, `db.query_rows`, `db.update_records` | yes: message handler |
| tool | tool | none | `file.read_internal`, `file.delete`, `web.fetch_page`, `tool.send_email_internal`, `tool.send_email_external`; also handles `admin.change_policy` when a scenario sends it there (M4), although the catalog serves it nobody | yes: message handler |
| malicious | none of its own: `AGENT_ROLE` must be set (Q2, credentials teammate) | whatever its token's role allows; as an impostor (`AGENT_NAME=<victim>`, `AGENT_IMPL=malicious`) it has the victim's name and role | none | no: step 12 paused |

Not in the catalog:

| Name | Notes |
|---|---|
| `admin.change_policy` | Prohibited: callers `[]`, `served_by: null`. |
| dummy | Test agent in the registry only (fixed reply, accepts tasks). Not a catalog agent and has no role, so it cannot mint tokens unless `AGENT_ROLE` is set. |

How the role is chosen at runtime (`wrapper/app.py`): `AGENT_ROLE` if set,
otherwise `AGENT_NAME` when it is a catalog role, otherwise no role.
