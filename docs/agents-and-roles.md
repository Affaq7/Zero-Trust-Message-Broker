# Agents and roles

Generated from `contracts/action_catalog.yaml` (v0.2, with the provisional
Q11 caller changes and the additive changes S10-S15 agreed by Kissa and Amna
on 2026-10-24; `schema_version` is still "0.2") and `wrapper/registry.py`.
The catalog is enforced by the broker only; direct mode ignores it.

| Agent | Role | Actions it may call | Actions it serves | Built and registered? |
|---|---|---|---|---|
| planner | planner | `db.query_aggregate`, `db.query_rows`, `db.update_records`, `file.read_internal`, `file.delete`, `tool.send_email_internal`, `tool.send_email_external`, `research.lookup` | `planner.request` | yes: message handler (still replies with an error, since it has no handler for `planner.request` yet) and task handler (`POST /task`, the entry point). The frozen prompt offers only the first seven actions: it neither offers nor sends `research.lookup` (S17) |
| research | research | `db.query_aggregate`, `file.read_internal`, `web.fetch_page`, `planner.request` | `research.lookup` | no: the contract side is in place (S10, S11), the agent is not built |
| database | database | none | `db.query_aggregate`, `db.query_rows`, `db.update_records` | yes: message handler |
| tool | tool | `mail.deliver` | `file.read_internal`, `file.delete`, `web.fetch_page`, `tool.send_email_internal`, `tool.send_email_external`; also handles `admin.change_policy` when a scenario sends it there (M4), although the catalog serves it nobody | yes: message handler. It does not call `mail.deliver` yet: it still sends mail to the mock sink over plain HTTP |
| mailer | mailer | none | `mail.deliver` | no: new role and agent in the catalog (S12, S15); no implementation yet. The mock mail sink is what a mailer would front |
| malicious | none of its own: `AGENT_ROLE` must be set (Q2, credentials teammate) | whatever its token's role allows; as an impostor (`AGENT_NAME=<victim>`, `AGENT_IMPL=malicious`) it has the victim's name and role | none | no: step 12 paused |

Every action in the catalog, with its caller and server:

| Action | Class | Caller | Served by | Resource |
|---|---|---|---|---|
| `db.query_aggregate` | Permitted | planner, research | database | `db:<table>` |
| `db.query_rows` | Conditional | planner | database | `db:<table>` |
| `db.update_records` | Conditional | planner | database | `db:<table>` |
| `file.read_internal` | Permitted | planner, research | tool | `file:/<path>` |
| `file.delete` | Conditional | planner | tool | `file:/<path>` |
| `web.fetch_page` | Permitted | research | tool | the URL |
| `tool.send_email_internal` | Permitted | planner | tool | `email:internal` |
| `tool.send_email_external` | Conditional | planner | tool | `email:external` |
| `research.lookup` | Permitted | planner | research | `research:query` |
| `planner.request` | Permitted | research | planner | `planner:request` (my choice, S11) |
| `mail.deliver` | Permitted | tool | mailer | `mail:outbound` (my choice, S12) |
| `admin.change_policy` | Prohibited | nobody | nobody | `policy:<id>` (M15) |

The catalog has no field for resources or risk ratings; resource names
live in this table and in `docs/open-questions.md`, ratings in S16.

Optional payload fields added without changing who may call anything:
`justification` (max 500 characters) on `db.query_rows`, `db.update_records`,
`file.delete` and `tool.send_email_external` only (S13); `cc` and `bcc`
(lists, same limits as `to`) on both email actions and `mail.deliver`, with
every recipient list normalised by `normalize_address` (strip, lowercase)
and aliases unsupported (S14).

Not in the catalog:

| Name | Notes |
|---|---|
| dummy | Test agent in the registry only (fixed reply, accepts tasks). Not a catalog agent and has no role, so it cannot mint tokens unless `AGENT_ROLE` is set. |

How the role is chosen at runtime (`wrapper/app.py`): `AGENT_ROLE` if set,
otherwise `AGENT_NAME` when it is a catalog role (planner, research,
database, tool, mailer), otherwise no role.
