# GCP Security Analysis Helpers for Code Mode — Design

Date: 2026-10-31
Status: approved 2026-10-31

## Intent

A small, public, pure-Python library (`gcp_policy_analyzer`) that a Code
Mode agent imports and calls inside a sandbox to do GCP security analysis.
The model writes short orchestration scripts composing the helpers; users
ask questions in natural language and never write code. The library turns
raw GCP policy/firewall/log data into a ranked, redacted insight that is
safe to return to the model.

Why: security teams need to answer both simple questions ("what changed
yesterday") and multi-step ones (filter + join + rank across IAM and
firewall data) without building a SOC platform. Code Mode supplies the
orchestration; this library supplies trustworthy, composable primitives.

## Audience

Public release. Primary users are security teams pointing it at their own
GCP data, with an LLM/Code Mode agent writing the glue code.

## Analyzed surfaces

- IAM allow policies (project, folder, organization)
- VPC firewall rules
- Network firewall policies (global and regional)
- Audit-log change records (and general log filtering/correlation)

## Goals

- Composable helper functions a model can chain with ordinary Python.
- Both canonical questions answerable with short scripts:
  1. "What changed yesterday" → ranked, redacted result.
  2. "Every change in the last 7 days that increased external exposure on
     production networks, joined to service accounts that already hold
     high-privilege IAM roles in the same project/folder, ranked by blast
     radius" → answerable by a short script using only these helpers +
     plain Python.
- Everything returned to the model passes through `redact_sensitive`.
- Pure Python, standard library only. No third-party dependencies.
- Clone-to-running-examples in under five minutes.

## Non-goals

- No GCP SDK / live API client. Data arrives as normalized JSON, either
  passed in directly or fetched from the broker (below).
- No continuous scanner, UI, multi-tenant platform, or SOC workflow.
- No credential handling anywhere in the library or sandbox.
- No full graph-based blast-radius engine — the simple version (affected
  resource count, external-exposure flag, production flag) is sufficient.
- The sandbox and the credential-holding broker are built elsewhere. This
  repo documents their contracts; it does not implement them.

## Anti-goals

- Returning raw service-account emails, long unredacted resource paths,
  or secret-like strings to the model — that failure breaks the trust
  story of the whole project.
- Heuristics that silently pretend to be ground truth. Every heuristic is
  documented as a heuristic, with overridable defaults.

## Architecture decisions (as decided)

### Network and credentials (decided)

The sandbox is not air-gapped: it may make network calls as needed. GCP
credentials never live inside the sandbox. A broker/proxy outside the
sandbox holds the credentials and attaches them; the library calls the
broker with plain unauthenticated-from-the-sandbox HTTP.

Data provisioning is operator-controlled, two paths (decided):
1. **Live (broker swap):** the operator configures the broker, outside
   the sandbox, with a read-only credential and the scopes it will
   serve. The sandbox calls the broker bare; the broker attaches the
   credential and returns only data. Authorization lives in broker
   config — the LLM can request a scope, never grant one; unconfigured
   scopes simply fail.
2. **File:** the operator exports the data (Asset Inventory dump,
   `gcloud` output, log extract) and places the JSON where the sandbox
   can read it. Scripts `json.load` the file and feed the loaders — no
   network at all. Examples and tests use this path with fixtures.

The user asking questions never supplies credentials or logs through
chat; they express only intent (which scope/window to analyze).

### Fetch lives in the library (decided — "Option B")

The package includes `fetch.py` so the model composes
`fetch → load → score → redact` entirely from helpers.

**Broker HTTP contract** (my call — the external broker implements this):

```
GET {base_url}/export?type={resource_type}&scope={scope}
  type  ∈ iam_policies | vpc_firewall_rules | network_firewall_policies
          | audit_changes | log_entries
  scope = projects/X | folders/N | organizations/N
  optional for audit_changes / log_entries: &start={iso8601}&end={iso8601}
→ 200, application/json, the normalized envelope below (the envelope may
  contain only the requested key)
```

`fetch.py` uses `urllib.request`, takes `base_url` as an explicit argument
(never from an environment variable), sets a timeout, and raises a clear
error on non-200 or malformed JSON. No retries, no auth headers, no
credential parameters — by design there is nothing secret to send.

### Change source: audit_changes is primary (designer call)

"What changed" questions are answered from the `audit_changes` feed —
the broker (or an export pipeline) supplies pre-extracted change records
for the window. `diff.py` is a secondary tool for teams that have two
point-in-time exports and want to compare them; it produces the same
`Change` records so everything downstream is shared. The broker contract
does not need point-in-time snapshot fetching. `analyze()` reads
`audit_changes` from the envelope.

### Record schema: GCP-native shapes (designer call)

Records inside the envelope use GCP's native shapes, so exports need
minimal massaging: IAM policies as Asset Inventory/`gcloud` output
(`bindings: [{role, members[]}]` plus a `resource` name), firewall rules
as `compute#firewall` fields, network firewall policies as
`compute#firewallPolicy` with rules, audit changes as a thin record
derived from Cloud Audit Log entries (`resource`, `resource_type`,
`action`, `before`, `after`, `timestamp`, `principal`). The README
documents each record shape precisely — that documentation is the
authoritative contract the external broker implements.

### Log entries are a distinct input (designer call)

The envelope and broker contract gain a fifth type, `log_entries`: raw
Cloud Audit Log entries (methodName, principalEmail, callerIp,
timestamp, resourceName, …). `audit_changes` are derived change records;
`log_entries` are the underlying evidence. `logs.py` filters log entries
and `correlate_changes_with_logs` attaches the entries that explain each
change.

### Data envelope

All loaders consume this normalized JSON shape, whether it came from the
broker, an Asset Inventory export, `gcloud` output, or a file:

```json
{
  "iam_policies": [...],
  "vpc_firewall_rules": [...],
  "network_firewall_policies": [...],
  "audit_changes": [...],
  "log_entries": [...]
}
```

### Production detection is label-only (decided)

`is_production(x)` returns True only when the resource carries a
production label (defaults: `env`/`environment` in
{`prod`, `production`}). No name-pattern guessing. README states plainly:
"label your production resources or this returns False". Label keys and
values are overridable via an optional parameter.

### Heuristics: opinionated defaults, simple overrides (decided)

High-privilege role list, toxic combinations, redaction patterns, and
production label conventions ship as module-level constants with
sensible defaults; functions accept optional overrides. No config files,
no plugin system — a team extends a list or passes a parameter.

## Built-in Code Mode runner (added by user decision)

Code Mode holds no LLM key and never calls a model — the LLM agent IS
the caller. The agent (outside: Claude Code, an Agent SDK app, any
orchestrator) writes the Python script itself and hands it to Code Mode
for execution. Code Mode's entire job: receive script → run it inside
the sandbox → return redacted stdout → log the exact code that ran.

The repo ships a basic Code Mode so it works out of the box: if the
caller brings their own runtime, they use that and import only the
library; otherwise the built-in Code Mode is the fallback.

The agent connects via MCP and discovers capabilities first (user
decision): nothing about the library is assumed to be baked into the
agent's prompt. Flow: question arrives → agent calls
`describe_capabilities` → agent writes the script from what it learned
→ agent calls `run_script` → redacted answer returns.

`codemode/mcp_server.py` — MCP server (JSON-RPC over stdio, stdlib
only) exposing exactly two tools:
- `describe_capabilities` — returns the library's function reference:
  signatures, one-line purpose per helper, the data types, and the
  canonical composition pattern (fetch → load → classify/score → blast
  radius → redact). Generated from the package's docstrings so it can't
  drift from the code.
- `run_script` — takes the agent's Python script, executes it via the
  executor, returns redacted stdout.

`codemode/executor.py`:
- `run_script(code: str, *, timeout=60) -> ExecutionResult` — executes
  the script in a restricted subprocess: clean environment (no
  inherited env vars), timeout, stdout/stderr captured, and the
  verbatim code logged (audit requirement).
- Runs inside the sandbox. Zero secrets anywhere in it: GCP data comes
  via the credential-holding broker, and no model call happens here —
  MCP is the agent reaching in, never Code Mode reaching out.
- The sandbox's egress allowlist needs exactly one entry: the GCP
  broker.

The executor is a reference implementation, not the production sandbox:
deny-by-default egress and real isolation remain the external sandbox
project's responsibility, and the README says so.

## Package layout

```
gcp_policy_analyzer/
  __init__.py      # re-exports the public API incl. analyze()
  fetch.py         # broker client (urllib, stdlib only)
  loaders.py       # JSON → dataclasses
  diff.py          # snapshot diffing → Change records
  scoring.py       # exposure + IAM risk scoring, change classification
  prioritize.py    # ranking + simple blast radius
  logs.py          # audit-log filtering/correlation helpers
  redact.py        # redact_sensitive — the mandatory exit filter
  helpers.py       # is_production, is_service_account, format_report
codemode/
  mcp_server.py    # MCP stdio server: describe_capabilities, run_script
  executor.py      # restricted-subprocess script execution + code logging
examples/
  what_changed_yesterday.py
  seven_day_exposure.py       # the canonical complex-question script
fixtures/
  synthetic.json              # covers all scenarios below
tests/
  test_scoring.py test_classify.py test_diff.py test_redact.py ...
README.md
pyproject.toml
```

## Core API

**fetch.py**
- `fetch_export(base_url: str, resource_type: str, scope: str, *, start=None, end=None, timeout=30) -> dict`
- `fetch_all(base_url: str, scope: str) -> dict` — full envelope.

**loaders.py**
- `load_iam_policies(data: dict) -> list[IamPolicy]`
- `load_vpc_firewall_rules(data: dict) -> list[VpcFirewallRule]`
- `load_network_firewall_policies(data: dict) -> list[NetworkFirewallPolicy]`
- `load_audit_changes(data: dict, resource_types: list[str] | None = None, start: datetime | None = None, end: datetime | None = None) -> list[Change]`

**diff.py**
- `diff_policies(old: list, new: list, resource_type: str) -> list[Change]`
- `Change` dataclass: resource, resource_type, action, before, after,
  timestamp, principal, risk_delta.

**scoring.py**
- `score_rule_exposure(rule) -> ExposureScore` — flags 0.0.0.0/0, all
  ports, missing logging, high priority, broad protocols.
- `score_iam_binding(binding) -> RiskScore` — flags high-privilege roles,
  service-account members, toxic combinations.
- `classify_change(change) -> ChangeClass` — enum: BroadenedAccess,
  RemovedProtection, ShadowCreated, LeastPrivilegeImproved, Neutral, Other.

**prioritize.py**
- `prioritize_changes(changes: list[Change]) -> list[PrioritizedChange]`
- `compute_blast_radius(change, context: dict | None = None) -> BlastRadius`
  — affected resource count, external-exposure flag, production flag.

**logs.py**
- `filter_log_entries(entries, *, principal=None, methods=None, start=None, end=None) -> list`
- `correlate_changes_with_logs(changes, entries) -> list` — attach the log
  entries that explain each change (who, when, from where — redacted on
  exit like everything else).

**redact.py**
- `redact_sensitive(obj: dict | list, *, patterns=None, salt=None) -> dict | list`
  — masks service-account emails (stable short hash so joins stay
  possible: `sa-a1b2c3@…`), shortens long resource paths to the
  meaningful tail, masks secret-like strings. Pure function, returns a
  copy. Deterministic so tests can assert exact output.
- Hash posture (decided): deterministic unsalted by default — redaction
  is hygiene (raw identifiers never enter model context) and the model
  can correlate the same account across runs. Teams needing a hard,
  irreversible boundary pass `salt=` (per-run random salt → no cross-run
  joins). Documented plainly in the README.
- Extensible via decorator (decided): built-in rules cover the basics; a
  user registers additional rules with
  `@register_redactor` on a `(obj) -> obj` function. Registered rules
  run after the built-ins inside every `redact_sensitive` call, so
  custom redaction applies everywhere automatically — including inside
  `analyze()` and `format_report()`.

**helpers.py**
- `is_production(change_or_rule, *, label_keys=None, label_values=None) -> bool`
- `is_service_account(binding_or_member) -> bool`
- `format_report(prioritized: list) -> dict` — stable final structure.

**Top level**
- `analyze(data: dict, start: datetime, end: datetime, resource_types: list[str] | None = None) -> dict`
  returning `{"summary": str, "prioritized": [...], "stats": {...}}`,
  already redacted. This is the one-call path for simple questions.

All major types are dataclasses. Enums for ChangeClass and severity.

## Redaction guarantee

Every documented path that returns data to the model ends in
`redact_sensitive`: `analyze()` calls it internally; `format_report()`
calls it internally; the reference scripts call it explicitly. Tests
assert that outputs of both examples contain no raw SA emails and no
unredacted full resource paths.

## Fixtures (synthetic.json)

Covers, minimum:
- one high-risk VPC rule change (0.0.0.0/0 opened on a prod-labeled
  network),
- one IAM over-privilege change (SA granted roles/owner),
- one neutral change,
- enough correlated data (IAM policies + audit changes + labels over a
  7-day window) that `seven_day_exposure.py` produces a non-trivial
  ranked answer,
- log entries that correlate with at least one change.

All fixture identifiers are obviously fake (`example-prod-project`,
`sa-demo@example-prod-project.iam.gserviceaccount.com`).

## Tests

Stdlib `unittest`, runnable with `python -m unittest`. Cover scoring,
classification, diff, redaction, label-based production detection, and
the end-to-end shape of `analyze()`. `fetch.py` is tested against a
local `http.server` stub or by mocking `urllib` — no real network in
tests.

## README contents

1. One-sentence problem statement.
2. Install + "run this" in under 5 minutes (`git clone`, no deps,
   `python examples/what_changed_yesterday.py`).
3. Function reference.
4. The simple example and the complex 7-day script with expected output
   shape.
5. "How a model should use this" — the complex script as the canonical
   pattern: fetch/load → filter (`classify_change`, `is_production`) →
   join (`load_iam_policies` + `score_iam_binding` +
   `is_service_account`) → `compute_blast_radius` + sort →
   `redact_sensitive`.
6. Secure-execution section: the calling Code Mode runtime is
   responsible for the sandbox, deny-by-default egress (allowlist the
   broker), keeping secrets out of the sandbox, and logging the exact
   code that ran. The broker contract is documented for whoever builds
   the broker.
7. Limitations: heuristics are heuristics; blast radius is the simple
   version; production detection is label-only.

## Acceptance criteria

- "What changed yesterday" produces a ranked, redacted result via
  `analyze()` or a 5-line script.
- The 7-day complex question is answered by `examples/seven_day_exposure.py`
  using only the helpers + plain Python.
- No raw service-account emails or long unredacted paths in any returned
  structure (tested).
- Pure Python stdlib; `python -m unittest` passes.
- Fresh clone to both examples running: under five minutes.
- An MCP client (e.g. Claude Code) can connect to
  `codemode/mcp_server.py`, call `describe_capabilities`, then
  `run_script` against the synthetic fixtures — no keys, no model
  calls from Code Mode's side, works offline.

## Left to the builder

- Exact dataclass field lists beyond those named above.
- Scoring weights and severity thresholds (document them as defaults).
- The redaction hash scheme details (must be deterministic and stable
  within a run).
- Internal structure of `prioritize_changes` ordering (blast radius
  first, then risk delta, then recency — or similar sensible ordering,
  documented).
- Fixture realism beyond the required scenarios.

## Calls made by the designer (not user-confirmed individually)

- Broker HTTP contract shape (section above).
- audit_changes is the primary change source; diff.py is secondary for
  two-snapshot comparison.
- Record schemas follow GCP-native shapes; the README's schema docs are
  the authoritative contract for the broker.
- `log_entries` added as a distinct envelope/broker type from
  `audit_changes`.
- Redacted SA emails keep a stable short hash so the model can still
  join/correlate entities across results.
- Repo home: this package is the content of `secureCM/`.
- Tests use stdlib `unittest` (keeps the zero-dependency promise).
- Redaction hashes: deterministic by default, optional `salt=` for a
  hard irreversible boundary (user did not pick; one parameter covers
  both postures).
- Code Mode holds no LLM key and makes no model calls — the external
  agent writes the scripts (user decision), connecting via MCP to
  discover capabilities first (user decision). `describe_capabilities`
  is generated from package docstrings so docs can't drift from code
  (designer call).
- Custom redaction via a `@register_redactor` decorator registry that
  runs after built-in rules in every `redact_sensitive` call.
