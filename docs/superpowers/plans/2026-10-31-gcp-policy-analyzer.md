# GCP Policy Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A public, pure-Python library (`gcp_policy_analyzer`) of composable GCP security-analysis helpers for Code Mode agents, plus an in-sandbox MCP Code Mode executor (`codemode/`).

**Architecture:** Dataclass-centric pipeline — fetch/load → diff/classify/score → blast radius/prioritize → redact — where every model-facing exit passes through `redact_sensitive`. Code Mode is a stdio JSON-RPC MCP server exposing `describe_capabilities` (docstring-generated) and `run_script` (clean-subprocess executor). No credentials, no model calls, no third-party deps anywhere.

**Tech Stack:** Python ≥ 3.11, standard library only. Tests: stdlib `unittest`.

**Spec:** `docs/superpowers/specs/2026-10-31-gcp-policy-analyzer-design.md`

## Global Constraints

- Standard library only — zero third-party dependencies, including in tests (spec: "Pure Python, standard library only").
- Python ≥ 3.11 (`datetime.fromisoformat` with `Z`, `X | Y` unions). Set `requires-python = ">=3.11"` in pyproject.
- Library reads no environment variables; `fetch.py` takes `base_url` as an explicit argument (spec).
- No network in tests — `fetch` tests use a local `http.server` stub (spec).
- Every model-facing return path ends in `redact_sensitive` (spec: redaction guarantee).
- Production detection is label-only: keys `("env", "environment")`, values `("prod", "production")` — never name patterns (spec).
- All fixture identifiers obviously fake (`example-prod-project`, `sa-demo@example-prod-project.iam.gserviceaccount.com`) (spec).
- Heuristic constants are module-level with override parameters — no config files (spec).
- All tests run via `python -m unittest discover -s tests -v`.

## Review Focus

Failure modes the spec implies but doesn't spell out; each has its pinned test in the owning task:

1. **Partial envelope** — a dict missing keys (or `{}`) passed to any loader must return `[]`, not raise `KeyError`; models will fetch single types. → Task 1.
2. **Timestamp forms** — audit records carry ISO-8601 strings with `Z`; window filtering must compare timezone-aware datetimes without raising, and naive `start`/`end` args must be treated as UTC. → Task 1.
3. **Redaction over arbitrary nesting** — SA emails buried in nested lists/dicts and non-string values (`None`, ints, datetimes) must be handled without crashing; datetimes serialize to ISO strings. → Task 2.
4. **Hostile/broken scripts in the executor** — infinite loop (timeout), nonzero exit, and stderr-only scripts must all return an `ExecutionResult`, never hang or raise through the MCP server. → Task 9.
5. **Broker failures** — non-200 response and malformed JSON must raise `BrokerError` with the URL and status in the message, not a bare `urllib`/`json` traceback. → Task 7.

---

## File Structure

```
gcp_policy_analyzer/__init__.py   # public API re-exports + analyze()
gcp_policy_analyzer/fetch.py      # BrokerError, fetch_export, fetch_all
gcp_policy_analyzer/loaders.py    # IamPolicy, IamBinding, VpcFirewallRule, NetworkFirewallPolicy, load_*
gcp_policy_analyzer/diff.py       # Change, diff_policies
gcp_policy_analyzer/scoring.py    # ExposureScore, RiskScore, ChangeClass, score_*, classify_change, HIGH_PRIVILEGE_ROLES, TOXIC_COMBINATIONS
gcp_policy_analyzer/prioritize.py # BlastRadius, PrioritizedChange, compute_blast_radius, prioritize_changes
gcp_policy_analyzer/logs.py       # filter_log_entries, correlate_changes_with_logs
gcp_policy_analyzer/redact.py     # redact_sensitive, register_redactor, clear_redactors
gcp_policy_analyzer/helpers.py    # is_production, is_service_account, format_report, PROD_LABEL_KEYS/VALUES
codemode/__init__.py
codemode/executor.py              # ExecutionResult, run_script
codemode/mcp_server.py            # stdio JSON-RPC MCP server
examples/what_changed_yesterday.py
examples/seven_day_exposure.py
fixtures/synthetic.json
tests/test_loaders.py test_redact.py test_scoring.py test_helpers.py
tests/test_prioritize.py test_diff.py test_logs.py test_fetch.py
tests/test_analyze.py test_examples.py test_executor.py test_mcp_server.py
README.md  pyproject.toml
```

Shared type decisions (used by every task; field names are binding):

```python
# loaders.py
@dataclass class IamBinding: role: str; members: list[str]
@dataclass class IamPolicy: resource: str; bindings: list[IamBinding]; labels: dict
@dataclass class VpcFirewallRule:
    name: str; network: str; direction: str; priority: int
    source_ranges: list[str]; allowed: list[dict]; denied: list[dict]
    disabled: bool; log_enabled: bool; labels: dict; raw: dict
@dataclass class NetworkFirewallPolicy: name: str; region: str | None; rules: list[dict]; raw: dict

# diff.py
@dataclass class Change:
    resource: str; resource_type: str; action: str          # CREATE|UPDATE|DELETE
    before: dict | None; after: dict | None
    timestamp: datetime; principal: str
    risk_delta: int = 0; labels: dict = field(default_factory=dict)

# scoring.py
class ChangeClass(Enum): BroadenedAccess; RemovedProtection; ShadowCreated; LeastPrivilegeImproved; Neutral; Other
@dataclass class ExposureScore: score: int; flags: list[str]
@dataclass class RiskScore: score: int; flags: list[str]; is_high_privilege: bool

# prioritize.py
@dataclass class BlastRadius: affected_resources: int; external_exposure: bool; production: bool; score: int
@dataclass class PrioritizedChange: rank: int; change: Change; change_class: ChangeClass; blast_radius: BlastRadius

# codemode/executor.py
@dataclass class ExecutionResult: stdout: str; stderr: str; returncode: int; timed_out: bool; code: str
```

### Task 1: Package scaffold, fixtures, loaders

**Files:**
- Create: `gcp_policy_analyzer/__init__.py` (empty for now), `gcp_policy_analyzer/loaders.py`, `gcp_policy_analyzer/diff.py` (Change dataclass only), `fixtures/synthetic.json`, `tests/test_loaders.py`
- Modify: `pyproject.toml` (name `gcp-policy-analyzer`, `requires-python = ">=3.11"`, no dependencies); delete leftover `main.py`

**Interfaces:**
- Produces: the dataclasses above; `load_iam_policies(data: dict) -> list[IamPolicy]`; `load_vpc_firewall_rules(data: dict) -> list[VpcFirewallRule]`; `load_network_firewall_policies(data: dict) -> list[NetworkFirewallPolicy]`; `load_audit_changes(data: dict, resource_types: list[str] | None = None, start: datetime | None = None, end: datetime | None = None) -> list[Change]`; `_parse_ts(value: str | datetime) -> datetime` (aware UTC).
- Produces: `fixtures/synthetic.json` — the envelope with all five keys, GCP-native record shapes, containing: a prod-labeled network's firewall rule opened to `0.0.0.0/0` (UPDATE, 2 days ago, principal `terraform-deployer@example-prod-project.iam.gserviceaccount.com`), an EGRESS deny-all rule DELETE by the same SA, an IAM UPDATE granting `roles/owner` to `sa-demo@example-prod-project.iam.gserviceaccount.com` (4 days ago), a description-only Neutral UPDATE by `alice@example.com`, one change 10 days old (outside any 7-day window), IAM policies where `terraform-deployer@…` holds `roles/editor` on `projects/example-prod-project`, a sixth top-level key `resources` listing 14 instance/subnet records `{"name", "network", "project"}` attached to the prod network (loaders ignore unknown envelope keys; `compute_blast_radius` reads `context["resources"]`) — plus `log_entries` (methodName, principalEmail, callerIp, timestamp, resourceName) matching the two firewall changes. Timestamps: ISO-8601 `Z` strings, relative to a fixed anchor `2026-10-31T00:00:00Z` (fixtures are static; examples compute windows against this anchor, not `now()`).

- [ ] **Step 1: Write failing tests** in `tests/test_loaders.py`:

```python
def test_load_iam_policies_from_fixture(self):      # len ≥ 1; bindings[0].role startswith "roles/"
def test_load_vpc_rules_parses_fields(self):        # finds rule with "0.0.0.0/0" in source_ranges; labels dict present
def test_load_audit_changes_window_filter(self):    # start/end naive datetimes → treated UTC; 10-day-old change excluded
def test_partial_envelope_returns_empty(self):      # every loader on {} returns [] (Review Focus 1)
def test_timestamp_z_suffix_parsed_aware(self):     # _parse_ts("2026-10-29T14:03:11Z").tzinfo is not None (Review Focus 2)
```

- [ ] **Step 2: Run** `python -m unittest tests.test_loaders -v` — expect FAIL (module not found / fixture missing)
- [ ] **Step 3: Implement** fixtures + dataclasses + loaders. Loaders use `data.get(key, [])`. `load_audit_changes` converts naive `start`/`end` to UTC via `.replace(tzinfo=timezone.utc)`.
- [ ] **Step 4: Run** `python -m unittest tests.test_loaders -v` — expect PASS
- [ ] **Step 5: Commit** `feat: package scaffold, synthetic fixtures, loaders`

### Task 2: redact.py

**Files:**
- Create: `gcp_policy_analyzer/redact.py`, `tests/test_redact.py`

**Interfaces:**
- Produces: `redact_sensitive(obj, *, patterns=None, salt=None) -> same-shape copy`; `register_redactor(fn)` decorator appending to module registry `_REDACTORS`; `clear_redactors()` (for test isolation); constant `SECRET_PATTERNS: list[re.Pattern]`.
- Behavior pinned by spec: SA email `local@proj.iam.gserviceaccount.com` → `sa-{sha256((salt or "")+email).hexdigest()[:6]}@…iam.gserviceaccount.com` (deterministic when salt is None); resource paths with ≥ 4 `/`-segments → `.../{seg[-2]}/{seg[-1]}`; strings matching `SECRET_PATTERNS` (at minimum `AIza[0-9A-Za-z_-]{35}` and `-----BEGIN( [A-Z]+)? PRIVATE KEY-----`) → `"[REDACTED]"`; datetimes → `.isoformat()`; dataclasses → `asdict` first; registered redactors run after built-ins, outermost object only.

- [ ] **Step 1: Write failing tests**:

```python
def test_sa_email_masked_deterministically(self):   # same email twice → identical sa-xxxxxx@… ; raw email absent
def test_salt_changes_hash(self):                   # salt="a" vs salt="b" → different masks
def test_long_path_shortened(self):                 # "projects/p/global/firewalls/f" → ".../firewalls/f"
def test_secret_string_redacted(self):              # "AIza" + 35 chars → "[REDACTED]"
def test_nested_and_nonstring_values(self):         # SA email 3 levels deep in list/dict masked; None/int/datetime survive (Review Focus 3)
def test_register_redactor_runs(self):              # custom rule replacing "10.0.0.5" applies; clear_redactors() in tearDown
```

- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement** — recursive walk returning copies; never mutate input.
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: redact_sensitive with decorator registry and salt option`

### Task 3: scoring.py + helpers.py (production/SA predicates)

**Files:**
- Create: `gcp_policy_analyzer/scoring.py`, `gcp_policy_analyzer/helpers.py` (predicates only; `format_report` arrives Task 4), `tests/test_scoring.py`, `tests/test_helpers.py`

**Interfaces:**
- Consumes: `VpcFirewallRule`, `Change` (Task 1).
- Produces: `score_rule_exposure(rule: VpcFirewallRule | dict) -> ExposureScore` — +40 flag `open_to_world` if `0.0.0.0/0` or `::/0` in source ranges; +20 `all_ports` (no ports listed or `0-65535`); +10 `logging_disabled`; +10 `high_priority` (priority < 1000); +20 `broad_protocol` (`all` protocol). `score_iam_binding(binding: IamBinding | dict, *, high_privilege_roles=None) -> RiskScore` — `is_high_privilege` iff role in `HIGH_PRIVILEGE_ROLES` = `{"roles/owner","roles/editor","roles/iam.securityAdmin","roles/iam.serviceAccountTokenCreator","roles/iam.serviceAccountKeyAdmin"}`; flags `service_account_member`, `toxic_combination` (role in `TOXIC_COMBINATIONS` set and any SA member). `classify_change(change: Change) -> ChangeClass` — BroadenedAccess: source ranges widened to world / new allow rule to world / high-priv role granted; RemovedProtection: deny rule or logging removed, DELETE of a deny rule; ShadowCreated: CREATE of a disabled or duplicate-priority rule; LeastPrivilegeImproved: high-priv role removed or ranges narrowed; Neutral: before/after differ only in `description`; else Other.
- Produces: `is_production(obj, *, label_keys=None, label_values=None) -> bool` (defaults `PROD_LABEL_KEYS=("env","environment")`, `PROD_LABEL_VALUES=("prod","production")`; accepts dataclass or dict, looks at `.labels`); `is_service_account(member: str | dict) -> bool` — strips `serviceAccount:` prefix, True iff email ends `.gserviceaccount.com`.

- [ ] **Step 1: Write failing tests** — one per rule above, driven by the fixture's three canonical changes:

```python
def test_world_open_rule_flags_and_score(self)      # open_to_world in flags, score ≥ 40
def test_roles_owner_is_high_privilege(self)
def test_classify_world_open_update_broadened(self) # fixture change #1 → BroadenedAccess
def test_classify_deny_delete_removed_protection(self)
def test_classify_description_only_neutral(self)
def test_is_production_label_only(self)             # labeled prod → True; name "prod-core" w/o label → False
def test_is_service_account_prefix_and_domain(self)
```

- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement** both modules
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: exposure/IAM scoring, change classification, prod+SA predicates`

### Task 4: prioritize.py + format_report

**Files:**
- Create: `gcp_policy_analyzer/prioritize.py`, `tests/test_prioritize.py`
- Modify: `gcp_policy_analyzer/helpers.py` (add `format_report`)

**Interfaces:**
- Consumes: `Change`, `classify_change`, `is_production`, `redact_sensitive`.
- Produces: `compute_blast_radius(change: Change, context: dict | None = None) -> BlastRadius` — `affected_resources` = count of `context["resources"]` records sharing the change's network (firewall changes) or project (IAM changes); fallback 1 when context is None or has no `resources`; `external_exposure` = classify says BroadenedAccess with world-open after-state; `production` = `is_production(change)`; `score = affected_resources * (2 if external_exposure else 1) * (2 if production else 1)`. `prioritize_changes(changes: list[Change], context: dict | None = None) -> list[PrioritizedChange]` — drops Neutral/Other into nothing (they're excluded), orders by `blast_radius.score` desc, then `risk_delta` desc, then `timestamp` desc; assigns `rank` from 1. `format_report(prioritized: list[PrioritizedChange]) -> dict` — returns `{"summary": str, "prioritized": [dict…], "stats": {"total_changes", "risky", "neutral", "principals"}}`, passed through `redact_sensitive` internally.

- [ ] **Step 1: Write failing tests**:

```python
def test_blast_radius_score_formula(self)        # 14 resources, external, prod → score 56
def test_prioritize_orders_and_ranks(self)       # fixture changes: world-open rule rank 1; neutral excluded
def test_format_report_is_redacted(self)         # json.dumps(report) contains no "@example-prod-project.iam.gserviceaccount.com"
```

- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: blast radius, prioritization, redacted report formatting`

### Task 5: diff.py

**Files:**
- Create: `tests/test_diff.py`
- Modify: `gcp_policy_analyzer/diff.py` (add `diff_policies`)

**Interfaces:**
- Consumes: loader dataclasses (Task 1).
- Produces: `diff_policies(old: list, new: list, resource_type: str) -> list[Change]` — keyed by `.resource` (IAM) or `.name` (firewall); emits CREATE for keys only in new, DELETE for only in old, UPDATE when `raw`/bindings differ; `timestamp=datetime.now(timezone.utc)`, `principal=""` (snapshots carry neither), before/after as dicts.

- [ ] **Step 1: Write failing tests** — `test_diff_detects_create_update_delete` (mutate a copied fixture list; assert one of each action), `test_diff_identical_lists_empty`.
- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: snapshot diffing to Change records`

### Task 6: logs.py

**Files:**
- Create: `gcp_policy_analyzer/logs.py`, `tests/test_logs.py`

**Interfaces:**
- Consumes: `Change`, `_parse_ts`.
- Produces: `filter_log_entries(entries: list[dict], *, principal=None, methods=None, start=None, end=None) -> list[dict]`; `correlate_changes_with_logs(changes: list[Change], entries: list[dict]) -> list[dict]` — per change returns `{"change": change, "evidence": [entries where principalEmail == change.principal and resourceName endswith change.resource's last 2 segments and |timestamp delta| ≤ 300s]}`.

- [ ] **Step 1: Write failing tests** — `test_filter_by_principal_and_window`, `test_correlate_attaches_matching_entry` (fixture firewall change gains ≥ 1 evidence entry; neutral change gains different evidence or none).
- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: log filtering and change-to-log correlation`

### Task 7: fetch.py

**Files:**
- Create: `gcp_policy_analyzer/fetch.py`, `tests/test_fetch.py`

**Interfaces:**
- Produces: `class BrokerError(Exception)`; `fetch_export(base_url: str, resource_type: str, scope: str, *, start=None, end=None, timeout=30) -> dict` — GET `{base_url}/export?type=…&scope=…[&start=…&end=…]` (urlencoded, datetimes → `.isoformat()`), parses JSON envelope; `fetch_all(base_url: str, scope: str, *, timeout=30) -> dict` — one call per resource type, merged envelope. On `nextPageToken` in a response, re-request with `&pageToken=…` and concatenate lists.

- [ ] **Step 1: Write failing tests** against a `http.server.ThreadingHTTPServer` on port 0 started in `setUpClass`:

```python
def test_fetch_export_returns_envelope(self)       # stub returns {"vpc_firewall_rules":[…]}
def test_pagination_followed(self)                 # stub pages 2 responses via nextPageToken → merged list
def test_non_200_raises_brokererror(self)          # 403 → BrokerError, message contains url and "403" (Review Focus 5)
def test_bad_json_raises_brokererror(self)
```

- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement** — `urllib.request.urlopen` only; no env reads, no auth headers, no retries.
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: credential-less broker client with pagination`

### Task 8: analyze() + public API + examples

**Files:**
- Create: `examples/what_changed_yesterday.py`, `examples/seven_day_exposure.py`, `tests/test_analyze.py`, `tests/test_examples.py`
- Modify: `gcp_policy_analyzer/__init__.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `analyze(data: dict, start: datetime, end: datetime, resource_types: list[str] | None = None) -> dict` in `__init__.py` — `load_audit_changes` → `prioritize_changes` → `format_report`, summary sentence includes counts and scope window. `__init__.py` re-exports: `analyze, fetch_export, fetch_all, BrokerError, load_iam_policies, load_vpc_firewall_rules, load_network_firewall_policies, load_audit_changes, diff_policies, Change, score_rule_exposure, score_iam_binding, classify_change, ChangeClass, prioritize_changes, compute_blast_radius, filter_log_entries, correlate_changes_with_logs, redact_sensitive, register_redactor, is_production, is_service_account, format_report` (this list is `__all__`).
- Produces: both example scripts read `fixtures/synthetic.json`, compute windows against the fixture anchor `2026-10-31T00:00:00Z`, and `print(json.dumps(result, indent=2))`. `seven_day_exposure.py` is the spec's canonical script: load changes (7d) → keep BroadenedAccess/RemovedProtection ∧ `is_production` → build high-priv SA set from `load_iam_policies` + `score_iam_binding` + `is_service_account` → keep changes whose principal is in the set → sort by `compute_blast_radius().score` desc → `redact_sensitive`.

- [ ] **Step 1: Write failing tests**:

```python
# test_analyze.py
def test_analyze_shape_and_redaction(self)   # keys summary/prioritized/stats; no raw SA email in json.dumps
def test_analyze_window_respects_bounds(self)
# test_examples.py — run each via subprocess [sys.executable, path], cwd=repo root
def test_yesterday_example_outputs_ranked_json(self)
def test_seven_day_example_nonempty_and_redacted(self)   # ≥1 hit; raw SA emails absent; ranks descend by score
```

- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement** `analyze`, `__all__`, both examples
- [ ] **Step 4: Run** — expect PASS; also run `python examples/seven_day_exposure.py` manually and eyeball output
- [ ] **Step 5: Commit** `feat: analyze() entry point, public API, canonical examples`

### Task 9: codemode/executor.py

**Files:**
- Create: `codemode/__init__.py`, `codemode/executor.py`, `tests/test_executor.py`

**Interfaces:**
- Produces: `run_script(code: str, *, timeout: int = 60, audit_log: str | None = None) -> ExecutionResult` — writes code to a temp file; runs `[sys.executable, tmppath]` with `env={"PYTHONPATH": repo_root}` (nothing else inherited — the sole env entry makes the library importable), `cwd=repo_root`, `subprocess.run(capture_output=True, timeout=…)`; on `TimeoutExpired` returns `ExecutionResult(timed_out=True, returncode=-1, …)`; before execution appends `{"ts": …, "code": code}` as a JSON line to `audit_log` (default `codemode_audit.jsonl` in cwd).

- [ ] **Step 1: Write failing tests**:

```python
def test_runs_script_and_captures_stdout(self)     # print("hi") → stdout "hi\n", returncode 0
def test_timeout_returns_result(self)              # while True: pass, timeout=1 → timed_out True (Review Focus 4)
def test_failing_script_captured(self)             # raise ValueError → returncode != 0, stderr has traceback (Review Focus 4)
def test_env_is_clean(self)                        # os.environ.get("HOME") prints None/empty inside script
def test_code_logged_verbatim(self)                # audit file line contains exact source
```

- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: clean-subprocess script executor with verbatim audit log`

### Task 10: codemode/mcp_server.py

**Files:**
- Create: `codemode/mcp_server.py`, `tests/test_mcp_server.py`

**Interfaces:**
- Consumes: `run_script` (Task 9), `gcp_policy_analyzer` docstrings.
- Produces: `build_capabilities() -> str` — walks `gcp_policy_analyzer.__all__`, emits per-symbol `inspect.signature` + first docstring line, plus the canonical pattern line `fetch → load → classify/score → blast radius → sort → redact`. `handle_request(req: dict) -> dict | None` — JSON-RPC 2.0: `initialize` (protocolVersion `2024-11-05`, serverInfo name `gcp-policy-analyzer-codemode`), `notifications/initialized` (no response), `tools/list` (two tools: `describe_capabilities` no-args; `run_script` with `{code: string, timeout?: int}`), `tools/call` (dispatch; result as `{"content":[{"type":"text","text": …}]}`), unknown method → error `-32601`. `main()` — line-delimited JSON over stdin/stdout loop.
- Every function in `gcp_policy_analyzer` must therefore carry a one-line docstring — add any missing ones in this task.

- [ ] **Step 1: Write failing tests** (call `handle_request` directly — no subprocess needed):

```python
def test_initialize_and_tools_list(self)           # two tools, names exact
def test_describe_capabilities_lists_api(self)     # text contains "analyze(" and "redact_sensitive(" and the pattern line
def test_run_script_tool_executes(self)            # code 'print(1+1)' → text contains "2"
def test_unknown_method_error(self)                # error code -32601
```

- [ ] **Step 2: Run** — expect FAIL
- [ ] **Step 3: Implement**; verify manually: `printf '…initialize…\n…tools/list…\n' | python codemode/mcp_server.py` returns two JSON lines
- [ ] **Step 4: Run** — expect PASS
- [ ] **Step 5: Commit** `feat: MCP stdio server with describe_capabilities and run_script`

### Task 11: README + final verification

**Files:**
- Create/Modify: `README.md`

**Interfaces:**
- Consumes: everything; the README's record-schema section is the authoritative broker contract (spec).

- [ ] **Step 1: Write README** with the spec's seven sections (§ "README contents"), plus: the record schemas for all five envelope types (authoritative broker contract), the broker HTTP contract verbatim from the spec, the operator provisioning note (broker-swap and file paths; users never paste credentials/logs into chat), the MCP quickstart (`claude mcp add gcp-analyzer -- python codemode/mcp_server.py`), the redaction posture (deterministic default, `salt=` for hard boundary, `@register_redactor`), and limitations (heuristics are heuristics; blast radius simple version; production label-only).
- [ ] **Step 2: Full suite** `python -m unittest discover -s tests -v` — all pass
- [ ] **Step 3: Five-minute check** — from repo root run both example commands exactly as the README states them; outputs match the README's "expected shape" blocks
- [ ] **Step 4: Grep guarantee** — `python examples/seven_day_exposure.py | grep -c 'example-prod-project.iam.gserviceaccount.com'` → 0 matches
- [ ] **Step 5: Commit** `docs: README with broker contract, schemas, secure-execution notes`
