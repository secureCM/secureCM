# ATT&CK Coverage System + Detection Helpers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A versioned ATT&CK Cloud/IaaS coverage ledger for `gcp_policy_analyzer`, plus the in-scope detection helpers that move its three-surface techniques to `covered`, with a report that measures coverage and fails on regression.

**Architecture:** One checked-in JSON catalog (the full matrix, each technique `covered`/`partial`/`not-covered`/`out-of-scope`) is the source of truth. Pure-function detectors over the existing envelope emit `Finding` objects carrying ATT&CK IDs. A signature registry maps technique→detector; a `python -m attack_coverage.report` runs each covered/partial detector against its fixture, prints the tactic matrix, and fails on regression or dangling catalog↔registry↔fixture references.

**Tech Stack:** Python ≥3.11, standard library only. Tests: stdlib `unittest`. Catalog: JSON (no YAML dependency).

**Spec:** `docs/superpowers/specs/2026-10-31-attack-coverage-system-design.md`

**Base:** builds on `gcp_policy_analyzer` incl. `correlate_by_actor` (currently on branch `feature/correlation-quality` — merge to `main` first; this plan branches from that).

## Global Constraints

- Python ≥3.11, standard library only — zero third-party deps, tests included.
- Do NOT change the approved library envelope, broker contract, or loaders. No new envelope keys. Scope is the three surfaces (IAM allow policies, VPC firewall rules, network firewall policies) + their audit-change and log trail only.
- Package name is `attack_coverage` (NOT `coverage` — avoids colliding with coverage.py). Report runs as `python -m attack_coverage.report`.
- Catalog is JSON at `attack_coverage/attack_catalog.json`; a header entry records the pinned ATT&CK version: **Enterprise v15.1**, platforms IaaS + cloud IAM.
- Detectors are pure functions over already-loaded data; no I/O, no env reads.
- Every `covered`/`partial` catalog entry names an existing `detector` and an existing `fixture`; every `out-of-scope` entry has a non-null `reason`. Enforced by the report.
- Tests run via `python -m unittest discover -s tests`.
- Commit messages end with the repo's Co-Authored-By trailer.

## Review Focus

1. **Partial/empty envelope** — any detector called on `{}` or a dict missing `audit_changes`/`iam_policies`/`vpc_firewall_rules` returns `[]`, never raises. → Tasks 2,3,4.
2. **No-op IAM re-grant** — a change whose `after` bindings add no member/role beyond `before` must NOT produce a privilege finding (avoid false positives on idempotent re-applies). → Task 3.
3. **Narrowing firewall change** — `0.0.0.0/0` → `10.0.0.0/8` (a fix) must NOT be flagged as exposure; only widening toward world/broad does. → Task 2.
4. **Dangling catalog reference** — a catalog entry naming a detector or fixture that doesn't exist must make the report FAIL loudly, not silently skip. → Tasks 1,7.
5. **In-scope decoy precision** — reverted dev firewall (opened then closed), approved external viewer, expected staging owner-SA must yield no finding or be separable, not inflate campaign counts. → Tasks 6,7.

---

## File Structure

```
attack_coverage/__init__.py
attack_coverage/attack_catalog.json   # full matrix ledger (source of truth)
attack_coverage/catalog.py            # load_catalog(), validate_catalog()
attack_coverage/signatures.py         # TECHNIQUE_DETECTOR registry, run_detectors()
attack_coverage/report.py             # python -m attack_coverage.report
gcp_policy_analyzer/detect.py         # Finding, detect_* helpers, cross_project_timeline
gcp_policy_analyzer/logs.py           # (modify) correlate_by_actor subnet support
gcp_policy_analyzer/__init__.py       # (modify) export new helpers
codemode/mcp_server.py                # (modify) coverage summary in describe_capabilities
fixtures/incidents/generate.py        # deterministic in-scope fixture generator
fixtures/incidents/*.json             # per-technique fixtures + inscope_haystack.json + ground_truth
README.md                             # (modify) coverage section
tests/test_catalog.py test_detect_firewall.py test_detect_privilege.py
tests/test_detect_misc.py test_signatures.py test_fixtures.py
tests/test_coverage_report.py tests/test_mcp_coverage.py
```

Shared types (binding across tasks):

```python
# gcp_policy_analyzer/detect.py
@dataclass
class Finding:
    technique_id: str            # e.g. "T1562.007"
    technique_name: str
    tactic: str
    severity: str                # "critical" | "high" | "medium" | "low"
    resource: str
    principal: str
    timestamp: "datetime | None"
    evidence: dict               # detector-specific detail

# attack_coverage/catalog.py — a catalog entry (dict) shape
# {"id","name","tactic","seen_in":[...],"status","detector"|null,
#  "fixture"|null,"verified"|null,"reason"|null,"signal"}
```

### Task 1: attack_coverage scaffold + catalog + validator

**Files:**
- Create: `attack_coverage/__init__.py`, `attack_coverage/attack_catalog.json`, `attack_coverage/catalog.py`, `tests/test_catalog.py`

**Interfaces:**
- Produces: `load_catalog(path: str | None = None) -> dict` (returns `{"attack_version": str, "techniques": [entry,...]}`); `validate_catalog(catalog: dict) -> list[str]` (returns a list of problem strings, empty if valid).
- The shipped catalog enumerates the ATT&CK v15.1 Cloud/IaaS matrix. In-scope entries (status + detector, names/tactics filled from v15.1):
  - `T1098` Account Manipulation — partial — `detect_privilege_grant`
  - `T1098.003` Additional Cloud Roles — covered — `detect_privilege_grant`
  - `T1199` Trusted Relationship — partial — `detect_privilege_grant`
  - `T1562` Impair Defenses — partial — `detect_firewall_exposure`
  - `T1562.007` Disable or Modify Cloud Firewall — covered — `detect_firewall_exposure`
  - `T1485` Data Destruction — partial (firewall/policy deletes only) — `detect_firewall_exposure`
  - `T1580` Cloud Infrastructure Discovery — partial — `detect_discovery_bursts`
  - `T1069.003` Permission Groups Discovery: Cloud Groups — partial — `detect_discovery_bursts`
  - `T1078.004` Valid Accounts: Cloud Accounts — partial — `detect_anomalous_actor`
  - out-of-scope-by-surface (reason `"surface not ingested: <surface>"`): `T1530`,`T1537` (storage); `T1496`,`T1578`,`T1578.001/.002/.003` (compute); `T1562.008` (logging sink); `T1098.001`,`T1550.001` (keys/tokens); `T1552.005` (instance metadata); the indirect-group path noted in `T1098.003.signal`.
  - out-of-scope-by-telemetry (reason `"no telemetry feed"`): `T1566`,`T1621`,`T1059`,`T1204`,`T1190`,`T1110`,`T1486`.

- [ ] **Step 1: Write failing tests** in `tests/test_catalog.py`:

```python
def test_catalog_loads_with_version(self):          # load_catalog()["attack_version"] == "15.1"
def test_inscope_techniques_present_with_detectors(self):  # T1562.007 covered + detector detect_firewall_exposure; T1098.003 covered; T1199 partial
def test_every_out_of_scope_has_reason(self):        # all status==out-of-scope entries have non-empty reason
def test_covered_partial_name_detector_and_fixture(self):  # every covered/partial has non-null detector and fixture
def test_validate_flags_missing_reason(self):        # validate_catalog on a mutated entry (out-of-scope, reason=None) returns a problem
```

- [ ] **Step 2: Run** `python -m unittest tests.test_catalog -v` — FAIL (module/catalog missing)
- [ ] **Step 3: Author** `attack_catalog.json` (fill names/tactics from ATT&CK v15.1) and implement `load_catalog`/`validate_catalog`. `validate_catalog` checks: out-of-scope⇒reason; covered/partial⇒detector and fixture non-null; no duplicate ids.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: ATT&CK coverage catalog + validator`

### Task 2: Finding + detect_firewall_exposure

**Files:**
- Create: `gcp_policy_analyzer/detect.py`, `tests/test_detect_firewall.py`

**Interfaces:**
- Consumes: `VpcFirewallRule`, `Change`, `NetworkFirewallPolicy` (existing loaders).
- Produces: `Finding` dataclass (fields above); `detect_firewall_exposure(rules: list, changes: list) -> list[Finding]`. Flags, each with its technique_id: a change WIDENING source ranges toward `0.0.0.0/0` or `::/0` (T1562.007, severity high; critical if prod-labeled); adding broad protocols/all-ports or admin/mining ports (22,3389,3333,4444,14444) to a world-open rule (T1562.007); deleting or disabling a deny rule, or raising a deny rule's priority so an allow shadows it (T1562.007, defense evasion); DELETE of a firewall/policy resource (T1485). A change that only NARROWS ranges (world→internal) yields no finding (Review Focus 3). Empty/partial input → `[]` (Review Focus 1).

- [ ] **Step 1: Write failing tests**:

```python
def test_world_open_widen_flags_T1562_007(self)      # 10.0.0.0/8 -> 0.0.0.0/0 => one Finding, technique_id "T1562.007"
def test_prod_label_makes_critical(self)
def test_deny_delete_flags(self)                     # DELETE of deny rule => Finding T1562.007
def test_priority_shadow_flags(self)                 # deny priority 100 -> 9000 => Finding
def test_narrowing_not_flagged(self)                 # 0.0.0.0/0 -> 10.0.0.0/8 => []  (Review Focus 3)
def test_fw_delete_flags_T1485(self)
def test_empty_envelope_returns_empty(self)          # detect_firewall_exposure([], []) == []  (Review Focus 1)
```

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `Finding` + `detect_firewall_exposure` (reuse `score_rule_exposure`/`classify_change` where natural; `is_production` for severity).
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: Finding + firewall exposure detector (T1562.007, T1485)`

### Task 3: detect_privilege_grant

**Files:**
- Create: `tests/test_detect_privilege.py`
- Modify: `gcp_policy_analyzer/detect.py`

**Interfaces:**
- Consumes: `IamPolicy`, `IamBinding`, `Change`, `score_iam_binding`, `is_service_account`.
- Produces: `detect_privilege_grant(iam_policies: list, changes: list) -> list[Finding]`. Flags, each with technique_id: an IAM `UPDATE` whose `after` adds a member to a high-privilege role not present in `before` (T1098.003, critical for owner/securityAdmin); a grant whose new member is an EXTERNAL identity — not `*.iam.gserviceaccount.com` and not the corporate domain(s) passed via `corp_domains: tuple[str,...] = ("acme.example.com",)` (T1199); a binding producing a toxic combination per `score_iam_binding` (T1098). Grants at `folders/` or `organizations/` scope get severity bumped (cascades). A re-grant adding nothing new over `before` yields no finding (Review Focus 2). Partial input → `[]`.
- Signature note: INDIRECT (group-based) escalation is explicitly NOT handled — documented in the catalog entry's `signal` as out-of-scope-by-surface.

- [ ] **Step 1: Write failing tests**:

```python
def test_owner_grant_flags_T1098_003(self)
def test_external_member_flags_T1199(self)           # member user:x@partner.example (non-corp, non-SA)
def test_folder_scope_bumps_severity(self)           # resource "folders/..." => higher severity than project
def test_toxic_combo_flagged(self)
def test_noop_regrant_not_flagged(self)              # after==before members => []  (Review Focus 2)
def test_partial_envelope_empty(self)
```

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `detect_privilege_grant`.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: privilege-grant detector (T1098, T1098.003, T1199)`

### Task 4: discovery + anomalous-actor detectors, correlate_by_actor subnet, timeline

**Files:**
- Create: `tests/test_detect_misc.py`
- Modify: `gcp_policy_analyzer/detect.py`, `gcp_policy_analyzer/logs.py`

**Interfaces:**
- Produces in `detect.py`: `detect_discovery_bursts(logs: list, *, window_seconds=300, min_calls=10) -> list[Finding]` — a principal making ≥`min_calls` list/get method calls (methodName containing `.list`/`.get`) on IAM/firewall resources within `window_seconds` (T1580; T1069.003 when the target is groups/permissions). `detect_anomalous_actor(changes: list, logs: list) -> list[Finding]` — a principal acting against these surfaces from an external or rotating caller IP (reuses `correlate_by_actor`'s anomalous/subnet output) (T1078.004). `cross_project_timeline(changes: list, logs: list, *, principal: str | None = None) -> list[dict]` — merge changes+logs for a principal (or all), sort by timestamp, each item `{ts, project, kind, resource, detail}`; `project` parsed from the resource path.
- Modifies `logs.py`: `correlate_by_actor(changes, entries, *, anomaly_threshold=0.25, min_events_for_anomaly=3, subnet_bits: int | None = None)`. When `subnet_bits` is set, ADD two keys to the result — `shared_subnets: {cidr: [actors]}` and per-actor `anomalous_subnets: [cidr]` — computed by masking IPv4 callerIps to `/subnet_bits` (ignore unparseable/!v4). `shared_ips`/`anomalous_ips`/`actors` stay exactly as today (default `subnet_bits=None` → no new keys). (Review: additive, contract preserved.)

- [ ] **Step 1: Write failing tests**:

```python
def test_discovery_burst_flags_T1580(self)           # 10 .list calls in 5 min by one principal => Finding
def test_anomalous_actor_rotating_subnet(self)       # principal on 2 IPs in one /24 not seen elsewhere => Finding T1078.004
def test_cross_project_timeline_orders_multi_project(self)  # events across 2 projects sorted ascending with project tags
def test_correlate_subnet_additive(self)             # subnet_bits=24 adds shared_subnets; shared_ips unchanged; default call has no subnet keys
def test_correlate_subnet_deterministic(self)        # tie order stable across PYTHONHASHSEED
```

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** the three detectors + the additive subnet support (stdlib `ipaddress` for masking).
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: discovery/anomalous-actor detectors, timeline, subnet correlation`

### Task 5: signature registry + run_detectors

**Files:**
- Create: `attack_coverage/signatures.py`, `tests/test_signatures.py`

**Interfaces:**
- Consumes: the detectors (Task 2-4), `load_catalog` (Task 1), the loaders.
- Produces: `TECHNIQUE_DETECTOR: dict[str, str]` mapping technique_id → detector function name for every in-scope covered/partial technique; `run_detectors(envelope: dict) -> list[Finding]` — loads rules/iam/changes/logs from the envelope and runs each distinct detector once, returning all findings; `findings_for_technique(findings: list, technique_id: str) -> list[Finding]`.
- Consistency: the set of technique_ids in `TECHNIQUE_DETECTOR` must equal the set of catalog entries with status covered/partial, and each named detector must exist in `gcp_policy_analyzer.detect`.

- [ ] **Step 1: Write failing tests**:

```python
def test_registry_matches_catalog(self)              # set(TECHNIQUE_DETECTOR) == {covered/partial ids in catalog}
def test_every_registry_detector_exists(self)        # each detector name resolves in gcp_policy_analyzer.detect
def test_run_detectors_on_fixture_returns_findings(self)  # on a crafted envelope, >=1 Finding, techniques tagged
def test_findings_for_technique_filters(self)
```

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `signatures.py`.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: technique→detector registry and run_detectors`

### Task 6: in-scope integration fixture generator + per-technique fixtures

**Files:**
- Create: `fixtures/incidents/generate.py`, generated `fixtures/incidents/*.json`, `tests/test_fixtures.py`

**Interfaces:**
- Consumes: nothing from the package at import (pure generator); produces JSON envelopes the loaders accept.
- Produces: `fixtures/incidents/generate.py` (seeded, deterministic — no `random` without a fixed seed, no wall-clock; anchor passed as a constant). Writes: a small per-technique fixture for each in-scope technique named in its catalog entry's `fixture`, each exercising exactly that detector; and `inscope_haystack.json` — ~10 projects under a folder/org hierarchy, 40+ day window, several thousand routine IAM/firewall changes, carrying the in-scope campaigns from the spec (folder/org role-grant to external cascading; firewall world-open across prod projects from rotating IPs; priority-shadow of a deny rule; external-partner editor grant; direct folder-scope owner/token-creator binding) plus the in-scope decoys (reverted dev firewall, approved external viewer, expected staging owner-SA, benign internal-range widen). Also writes `inscope_ground_truth.json` listing each campaign's technique ids + the decoys. **Every event is resource_type iam_policy / firewall_rule / network_firewall_policy or a log entry over those — assert no other resource_type appears.**

- [ ] **Step 1: Write failing tests**:

```python
def test_generator_is_deterministic(self)            # run twice -> identical bytes
def test_haystack_only_inscope_resource_types(self)  # every audit_change.resource_type in {iam_policy, firewall_rule, network_firewall_policy}
def test_haystack_contains_each_campaign(self)        # ground truth lists >=5 campaigns; each present
def test_per_technique_fixtures_exist(self)          # for each covered/partial catalog entry, its fixture file exists and loads
def test_decoys_present(self)                         # reverted-firewall pair and approved-viewer present
```

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `generate.py`; run it to emit the JSON files; commit the generated fixtures too.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: in-scope (three-surface) incident fixtures + generator`

### Task 7: coverage report

**Files:**
- Create: `attack_coverage/report.py`, `tests/test_coverage_report.py`

**Interfaces:**
- Consumes: `load_catalog`, `validate_catalog`, `TECHNIQUE_DETECTOR`, `run_detectors`, `findings_for_technique`, the per-technique fixtures.
- Produces: `build_report(catalog=None) -> dict` — `{"by_tactic": {tactic: {covered,partial,not_covered,out_of_scope,total}}, "coverage": float, "regressions": [...], "dangling": [...], "not_covered": [...]}`. Coverage = covered / (total − out_of_scope). A technique is a REGRESSION if covered/partial but running its detector on its fixture yields no finding of that id. DANGLING if its detector or fixture is missing. `main()` prints the tactic matrix + coverage % + the not-covered queue + out-of-scope list, and exits nonzero if regressions or dangling exist. Runnable as `python -m attack_coverage.report`.

- [ ] **Step 1: Write failing tests**:

```python
def test_report_metric_excludes_out_of_scope(self)
def test_shipped_catalog_has_no_regressions(self)    # build_report()["regressions"] == []
def test_shipped_catalog_has_no_dangling(self)       # [] (Review Focus 4)
def test_dangling_detector_is_caught(self)           # mutate catalog: fixture="nope.json" -> appears in dangling
def test_no_inscope_left_not_covered(self)           # not_covered queue empty for the shipped catalog
```

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `report.py`; run `python -m attack_coverage.report` and confirm a clean matrix.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: coverage report with regression + dangling-reference gates`

### Task 8: describe_capabilities coverage summary, exports, README

**Files:**
- Modify: `codemode/mcp_server.py`, `gcp_policy_analyzer/__init__.py`, `README.md`
- Create: `tests/test_mcp_coverage.py`

**Interfaces:**
- Consumes: `build_report` (Task 7), the detectors (Tasks 2-4).
- Produces: `__init__.py` adds to `__all__` and imports: `Finding`, `detect_firewall_exposure`, `detect_privilege_grant`, `detect_discovery_bursts`, `detect_anomalous_actor`, `cross_project_timeline`. `describe_capabilities` preamble gains a COVERAGE block: the one-line coverage metric and a line pointing agents to `run_detectors(envelope)` for ATT&CK-tagged findings, and names the in-scope technique set. README gains a "Coverage" section: how the catalog/report work, the `python -m attack_coverage.report` command, the three-surface scope and why most of the matrix is out-of-scope.

- [ ] **Step 1: Write failing tests** in `tests/test_mcp_coverage.py`:

```python
def test_preamble_has_coverage_and_run_detectors(self)  # describe_capabilities text contains "run_detectors(" and "T1562.007"
def test_new_helpers_exported(self)                      # gcp_policy_analyzer.__all__ superset of the six names
```

- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** exports, preamble block, README section.
- [ ] **Step 4: Run** — PASS; then full suite `python -m unittest discover -s tests` and `python -m attack_coverage.report`.
- [ ] **Step 5: Commit** `docs: coverage in describe_capabilities, exports, README`
