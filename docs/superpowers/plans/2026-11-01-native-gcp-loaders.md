# Native-GCP Loaders Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `gcp_policy_analyzer` consume Google-published native GCP shapes (IAM allow policies, VPC firewall rules, network firewall policies — plus SA-key and group enabler events for correlation), deriving changes from the audit-log stream, while emitting the unchanged dataclasses so all detectors/scoring/coverage stay intact.

**Architecture:** Loaders become the normalizer. Changes are logs-primary: IAM from `SetIamPolicy.policyDelta`, firewall/network-policy by in-window replay of each resource's own audit history (baseline gaps reported, not guessed). A `flatten_log_entry` bridges native `LogEntry` to the flat view `logs.py` already uses. The broker/`fetch` becomes a pass-through. Dataclasses are the frozen internal boundary — nothing downstream of the loaders changes.

**Tech Stack:** Python ≥3.11, standard library only. Tests: stdlib `unittest`.

**Spec:** `docs/superpowers/specs/2026-11-01-native-gcp-loaders-design.md`

**Base:** builds on the existing library on `main` (post `18e4541`).

## Global Constraints

- Python ≥3.11, stdlib only — zero third-party deps, tests included.
- **Do NOT modify any dataclass** (`IamPolicy`, `IamBinding`, `VpcFirewallRule`, `NetworkFirewallPolicy`, `Change`, `Finding`). They are the contract that keeps `detect.py`, `scoring.py`, `redact.py`, `prioritize.py`, `analyze`, and `attack_coverage/*` untouched. If a native field has nowhere to go (e.g. IAM binding `condition`), drop it and note it — do not grow a dataclass.
- Scope = three surfaces only (IAM allow policies project/folder/org; VPC firewall rules; network firewall policies global+regional). SA-key and group-membership events are ingested as **correlation context only** (log entries), never emitted as in-scope `Change` records, never scored as state.
- Native shapes follow Google's published schemas (Cloud Audit `LogEntry`/`AuditLog`, `compute#firewall`, `compute#firewallPolicy`, `getIamPolicy`/Cloud Asset Inventory). No live GCP, no network in tests.
- Change derivation is logs-primary; `diff_policies` (two snapshots) remains a secondary mode, not required.
- `Change.before = None` means "baseline predates window" — a first-class, reported state; before-needing detectors must tolerate it.
- All tests run via `python -m unittest discover -s tests`; `python -m attack_coverage.report` must still exit 0.
- Commit messages end with the repo's Co-Authored-By trailer.

## Review Focus

1. **Partial patch merge** — a `compute.firewalls.patch` request carrying only changed fields must merge onto the replayed running state, not replace it (else `before`/`after` are wrong). → Task 3.
2. **Baseline gap** — a resource whose first in-window event is `patch`/`delete` with no prior in-window `insert` yields `before=None` + reason; before-needing detectors (priority-shadow, deny-delete) abstain without crashing. → Tasks 3, 5.
3. **Asset-wrapped vs bare** — state loaders accept both the bare native object and the Cloud Asset Inventory wrapper (`{name, asset_type, resource/iam_policy: {...}}`). → Task 4.
4. **`callerIp` carried** — `flatten_log_entry` must emit `callerIp` from `protoPayload.requestMetadata.callerIp`; dropping it silently blanks `correlate_by_actor`. → Task 1.
5. **Enabler events don't leak into changes** — SA-key/group events reach correlation but must NOT become firewall/IAM `Change` records nor be scored as state. → Tasks 2, 5.

---

## File Structure

```
gcp_policy_analyzer/loaders.py   # (modify) flatten_log_entry, load_log_entries, native state parsing, load_audit_changes rewrite
gcp_policy_analyzer/enrich.py    # (create) enabler-event correlation enrichment
gcp_policy_analyzer/__init__.py  # (modify) export flatten_log_entry, load_log_entries, enrich_with_enablers
gcp_policy_analyzer/fetch.py     # (modify) pass-through semantics / native types
attack_coverage/attack_catalog.json # (modify) T1098.001 + indirect T1098.003 -> partial
fixtures/**                      # (migrate) native Google shapes; generate.py updated
README.md                        # (modify) native envelope, logs-primary, broker pass-through
tests/test_loaders_native.py tests/test_audit_changes.py tests/test_enrich.py  # (create)
tests/* fixtures/*               # (update) existing tests/examples to native fixtures
```

Method-family constants (Task 1 defines; later tasks consume):
```
IAM_CHANGE_METHODS   = {"SetIamPolicy", "google.iam.v1.IAMPolicy.SetIamPolicy"}
FW_CHANGE_METHODS    = prefixes "compute.firewalls." / "v1.compute.firewalls." + {insert,patch,delete}
NFP_CHANGE_METHODS   = "...networkFirewallPolicies." + {insert,patch,delete,addRule,patchRule,removeRule} (global+regional)
ENABLER_METHODS      = {"google.iam.admin.v1.CreateServiceAccountKey","...DeleteServiceAccountKey","...UploadServiceAccountKey",
                        "google.admin.directory.member.insert","google.admin.directory.member.delete"}
```

### Task 1: flatten_log_entry + load_log_entries

**Files:** Modify `gcp_policy_analyzer/loaders.py`; Create `tests/test_loaders_native.py`

**Interfaces:**
- Produces: `flatten_log_entry(entry: dict) -> dict` — maps a native `LogEntry` to `{methodName, principalEmail, callerIp, resourceName, timestamp, serviceData, request}` reading `protoPayload.methodName`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, `protoPayload.resourceName`, top-level `timestamp`, and passing through `protoPayload.serviceData`/`request` for downstream change derivation. Missing fields → "" (or {}), never raise.
- Produces: `load_log_entries(data: dict) -> list[dict]` — flattens `data.get("log_entries", [])`; keeps only entries whose `methodName` is in the three surfaces' change methods OR `ENABLER_METHODS`; returns flattened dicts. Also accepts already-flat entries (idempotent) so `correlate_by_actor`/`filter_log_entries` can consume the output directly.
- Produces the method-family constants above.

- [ ] **Step 1: Write failing tests** in `tests/test_loaders_native.py`:
```python
def test_flatten_carries_callerip_and_core_fields(self)   # native LogEntry -> callerIp from protoPayload.requestMetadata.callerIp, + methodName/principalEmail/resourceName/timestamp
def test_flatten_missing_fields_no_raise(self)            # {} -> dict with "" fields, no exception
def test_load_log_entries_filters_to_known_methods(self)  # a storage.objects.list entry is dropped; a SetIamPolicy and a CreateServiceAccountKey are kept
def test_load_log_entries_idempotent_on_flat(self)        # passing already-flat entries returns them unchanged
```
- [ ] **Step 2: Run** `python -m unittest tests.test_loaders_native -v` — FAIL
- [ ] **Step 3: Implement** `flatten_log_entry`, `load_log_entries`, constants.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: flatten native LogEntry + windowed log loader`

### Task 2: load_audit_changes — IAM from policyDelta

**Files:** Modify `gcp_policy_analyzer/loaders.py`; Create `tests/test_audit_changes.py`

**Interfaces:**
- Consumes: `flatten_log_entry`/`load_log_entries`, constants (Task 1); `Change` (unchanged).
- Produces: internal `_iam_changes_from_logs(flat_entries) -> list[Change]` and wires it into `load_audit_changes`. For each `SetIamPolicy` entry, read `serviceData.policyDelta.bindingDeltas` (fallback `protoPayload.metadata`); emit ONE `Change` per entry: `resource_type="iam_policy"`, `action="UPDATE"`, `resource`=resourceName, `principal`=principalEmail, `timestamp` parsed UTC, `after={"bindings": [{role, members}]}` built from `ADD` deltas grouped by role, `before={"bindings": [...]}` from `REMOVE` deltas. Enabler/other methods produce NO change here (Review Focus 5).
- **Dual-mode during transition (keeps suite green):** `load_audit_changes` uses the legacy `data["audit_changes"]` list if present; otherwise derives from `data["log_entries"]`. Legacy path removed in Task 7's cutover.

- [ ] **Step 1: Write failing tests**:
```python
def test_setiampolicy_add_becomes_grant_change(self)   # ADD roles/owner user:x -> Change.after bindings has (roles/owner, user:x), before lacks it; detect_privilege_grant fires T1098.003
def test_setiampolicy_remove_is_not_a_grant(self)      # REMOVE -> member in before not after; detect_privilege_grant yields no grant
def test_enabler_methods_emit_no_iam_change(self)      # a CreateServiceAccountKey entry -> 0 Changes from load_audit_changes
```
- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `_iam_changes_from_logs`, call it from `load_audit_changes` for IAM.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: derive IAM changes from SetIamPolicy policyDelta`

### Task 3: load_audit_changes — firewall/nfp replay with baseline gaps

**Files:** Modify `gcp_policy_analyzer/loaders.py`; Modify `tests/test_audit_changes.py`

**Interfaces:**
- Produces: `_config_changes_from_logs(flat_entries) -> list[Change]`. Per resource (`resourceName`), order events by timestamp; carry a running reconstructed state dict seeded by the first in-window `insert`'s `request`. For each event emit `Change(resource, resource_type in {firewall_rule, network_firewall_policy}, action, before=<state before event or None>, after=<state after event>, principal, timestamp)`. `action`: `insert`→CREATE, `delete`→DELETE, `patch`/`*Rule`→UPDATE. `patch` MERGES its `request` onto the running state (partial patch), not replace. If a resource's first in-window event is `patch`/`delete` with no prior `insert`, set `before=None` and record `labels={"baseline":"predates_window"}` (reason surfaced). `resource_type` chosen by resourceName path (`/firewalls/` vs `/firewallPolicies/`).
- Downstream contract: `detect_firewall_exposure` already treats `before=None`/`{}` as not-world, so world-open still fires; priority-shadow/deny-delete branches read `before` and naturally abstain when it is None.

- [ ] **Step 1: Write failing tests**:
```python
def test_insert_then_patch_world_open_fires(self)        # insert (10.0.0.0/8) then patch (0.0.0.0/0) -> Change before has /8, after world; detect_firewall_exposure T1562.007
def test_partial_patch_merges_not_replaces(self)         # insert full rule, patch only {priority} -> after still has original sourceRanges/allowed (merge)
def test_baseline_gap_sets_before_none(self)             # first event is a patch, no prior insert -> before is None, labels.baseline == "predates_window", no crash
def test_priority_shadow_detected_via_replay(self)       # insert deny pri=100 then patch pri=9000 -> detect_firewall_exposure fires (campaign C equivalent)
def test_nfp_world_open_via_replay(self)                 # networkFirewallPolicies addRule allow 0.0.0.0/0 -> Change resource_type network_firewall_policy, detector fires
```
- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `_config_changes_from_logs` (replay + merge + baseline-gap), wire into `load_audit_changes`.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: firewall/nfp change replay with baseline-gap reporting`

### Task 4: Native state loaders (bare + Asset-Inventory-wrapped)

**Files:** Modify `gcp_policy_analyzer/loaders.py`; Modify `tests/test_loaders_native.py`

**Interfaces:**
- Modify `load_iam_policies`, `load_vpc_firewall_rules`, `load_network_firewall_policies` to accept native records — both bare (`getIamPolicy` / `compute#firewall` / `compute#firewallPolicy`) and Cloud Asset Inventory wrappers (`{name: "//…/projects/X", asset_type, resource: {data:{…}}}` or `{…, iam_policy:{bindings}}`), taking `resource` from the asset `name` when not inline. Still emit the unchanged dataclasses. IAM binding `condition` is dropped (no dataclass field; noted). `logConfig.enable`→`log_enabled`; full native object→`raw` (firewall/nfp). Existing normalized shapes still parse (they are near-native) — keep that path working until Task 7's cutover.

- [ ] **Step 1: Write failing tests**:
```python
def test_iam_asset_wrapped_resource_from_name(self)      # {name:"//cloudresourcemanager.googleapis.com/folders/77", iam_policy:{bindings}} -> IamPolicy.resource == "folders/77"
def test_firewall_native_compute_kind_parses(self)       # {"kind":"compute#firewall","logConfig":{"enable":true},...} -> VpcFirewallRule.log_enabled True, raw present
def test_nfp_regional_vs_global(self)                    # record with region -> NetworkFirewallPolicy.region set; without -> None
def test_member_prefixes_preserved(self)                 # serviceAccount:/user:/group: members kept verbatim
```
- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** native parsing in the three state loaders.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: native + asset-wrapped parsing in state loaders`

### Task 5: Enabler-event enrichment + catalog reclassification

**Files:** Create `gcp_policy_analyzer/enrich.py`; Modify `gcp_policy_analyzer/__init__.py`, `attack_coverage/attack_catalog.json`; Create `tests/test_enrich.py`

**Interfaces:**
- Consumes: `Change`, `load_log_entries`, flattened entries.
- Produces: `enrich_with_enablers(changes: list[Change], flat_logs: list[dict], *, window_seconds: int = 86400) -> list[Change]` — for each in-scope `Change`, if the change's `principal` had an `ENABLER` event (SA-key create / group member add) within `window_seconds` before the change, annotate `change.labels["enabler"]` with `{method, enabler_ts}` and bump an accompanying note; return the changes (enabler events themselves are NEVER turned into changes). Pure, order-stable.
- Catalog: set `T1098.001` and the indirect-group `T1098.003` note from `out-of-scope` to `partial`, `detector: enrich_with_enablers`, with a per-technique fixture path (created in Task 7). `__init__.py` exports `flatten_log_entry, load_log_entries, enrich_with_enablers`.

- [ ] **Step 1: Write failing tests**:
```python
def test_keymint_before_inscope_change_annotates(self)   # CreateServiceAccountKey for sa Y at t, then Y makes an IAM/firewall Change at t+1h -> that Change.labels["enabler"].method contains "CreateServiceAccountKey"
def test_group_add_before_change_annotates(self)         # member.insert then a change by that member -> annotated
def test_enabler_without_followon_change_no_output(self) # enabler event but no later in-scope change by that principal -> no change annotated, no spurious Change created
def test_catalog_reclassified_partial(self)              # load_catalog: T1098.001 status == "partial" with a detector + fixture
```
- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** `enrich.py`, exports, catalog edits.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: enabler-event (SA key / group) correlation enrichment`

### Task 6: fetch/broker pass-through

**Files:** Modify `gcp_policy_analyzer/fetch.py`; Modify `tests/test_fetch.py`

**Interfaces:**
- `fetch_export`/`fetch_all` unchanged in signature; semantics documented and tested as a **pass-through**: whatever native JSON the broker returns under each type key is returned verbatim (no transformation in the client). Add `log_entries` and the enabler event types to the set `fetch_all` requests; retire `audit_changes` as a fetched type (changes are derived from `log_entries`). The broker is documented as a credentialed forwarder that performs no normalization.

- [ ] **Step 1: Write failing tests** (against the existing local `http.server` stub):
```python
def test_fetch_all_requests_log_entries_not_audit_changes(self)  # fetch_all issues a log_entries request and no audit_changes request
def test_fetch_returns_native_verbatim(self)                     # stub returns a native LogEntry; fetch returns it unchanged (no flattening client-side)
```
- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Implement** the type-set change; confirm no client-side transformation.
- [ ] **Step 4: Run** — PASS
- [ ] **Step 5: Commit** `feat: broker/fetch pass-through for native GCP`

### Task 7: Native fixtures migration + cutover

**Files:** Migrate `fixtures/synthetic.json`, `fixtures/incidents/*.json`, `fixtures/incidents/generate.py`; Modify `gcp_policy_analyzer/loaders.py` (remove legacy normalized branches); update any tests/examples that embed normalized records.

**Interfaces:**
- Regenerate all fixtures to native Google shapes: IAM state as `getIamPolicy`/asset-wrapped; firewall/nfp as `compute#firewall`/`compute#firewallPolicy`; **changes expressed as native `LogEntry` audit entries** (`SetIamPolicy` with `policyDelta`, `compute.firewalls.*`/`networkFirewallPolicies.*` with `request`), replacing the old `audit_changes` key; add SA-key and group enabler `LogEntry`s where campaigns use them; per-technique fixtures for the reclassified `T1098.001` / indirect `T1098.003`. `generate.py` emits native, deterministic (fixed seed + anchor).
- Cutover: once fixtures are native, remove the legacy normalized parsing branches added for transition in Tasks 2-4; loaders are native-only.
- Invariant: `analyze`, every detector, and `python -m attack_coverage.report` produce the SAME verdicts (six campaigns + decoys) on the native fixtures as before. The attack_coverage per-technique fixtures still fire their technique ids.

- [ ] **Step 1: Write/adjust failing tests** — the coverage-report regression test and `test_examples`/`test_analyze` now point at native fixtures; they fail until migration done.
```python
def test_coverage_report_no_regressions_on_native(self)  # build_report() regressions == [] and not_covered == [] on native fixtures
def test_every_change_derived_from_logs(self)            # loaded haystack has NO top-level audit_changes key; changes come only from log_entries
def test_six_campaigns_still_detected(self)              # run_detectors on native haystack still yields the six campaigns' technique ids
```
- [ ] **Step 2: Run** — FAIL
- [ ] **Step 3: Migrate** fixtures + `generate.py` to native; run generator; remove legacy loader branches.
- [ ] **Step 4: Run** full suite + `python -m attack_coverage.report` — PASS / exit 0
- [ ] **Step 5: Commit** `feat: migrate fixtures to native GCP shapes; native-only loaders`

### Task 8: README + final verification

**Files:** Modify `README.md`

**Interfaces:**
- README updated: the input is **native Google-published GCP** (no normalized envelope); the broker is a credentialed **pass-through**; change derivation is **logs-primary** (policyDelta for IAM, in-window replay for firewall/nfp) with **baseline-gap** behavior documented; SA-key and group events are ingested as correlation context (not surfaces); the three-surface scope and the data each surface needs (current state optional; audit logs for the window required). Record-shape section points at Google's published schemas instead of a custom envelope.

- [ ] **Step 1: Write README** sections above (replace the old envelope/broker-contract sections).
- [ ] **Step 2: Full suite** `python -m unittest discover -s tests -v` — all pass.
- [ ] **Step 3: Coverage gate** `python -m attack_coverage.report` — exit 0, zero regressions/dangling.
- [ ] **Step 4: Examples** — run both example scripts against native fixtures; outputs match README shapes; `grep` guarantee: no raw SA local-parts in example output.
- [ ] **Step 5: Commit** `docs: README for native-GCP input, logs-primary changes, pass-through broker`
