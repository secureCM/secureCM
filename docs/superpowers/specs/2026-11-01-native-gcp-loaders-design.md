# Native-GCP Loaders (Google-Published Schema) — Design

Date: 2026-11-01
Status: draft, pending approval
Supersedes the "normalized envelope + external normalizer broker" input model of
2026-10-31-gcp-policy-analyzer-design.md. Detectors, scoring, redaction, the
ATT&CK coverage system, and the Code Mode sandbox are unchanged.

## Intent

Make the library consume **Google's published GCP shapes directly** instead of a
custom normalized envelope. The loaders become the normalizer — in-repo, tested,
versioned — so no external party has to learn or implement a mapping. The broker
drops from a transformer to a credentialed pass-through.

Driving reason: the normalized envelope pushed an ambiguous, untestable
transformation onto an unbuilt external broker (the "how does someone outside
normalize?" gap). Parsing Google's own published shapes removes that gap and
makes fidelity true by construction.

## Scope (hard limit — decided)

The universe is exactly three surfaces, GCP only:
1. **IAM allow policies** at project, folder, and organization scope.
2. **VPC firewall rules.**
3. **Network firewall policies**, global and regional.

Plus the **Cloud Audit Log method families that change those three surfaces**.

**Exception — service-account key events are ingested as correlation context
(decided):** an SA key is not a surface we manage, but a key-*creation* event is
the precursor that lets a compromised service account make changes to the three
surfaces (the "mint a key → that SA opens a firewall / grants a role" pivot). So
the SA-key audit-log event family —
`google.iam.admin.v1.CreateServiceAccountKey` (+ `DeleteServiceAccountKey`,
`UploadServiceAccountKey`) — IS ingested as `log_entries` and used ONLY for
correlation: it flows through `correlate_by_actor` and `cross_project_timeline`,
and a light enrichment links a key-mint for SA `Y` to a subsequent in-scope
change by `Y`, elevating that change's severity with a persistence-precursor
note. We do NOT enumerate or score key *state* — it is the event we watch, not a
fourth surface (no new state loader). This reclassifies catalog entry
`T1098.001` from `out-of-scope (no key surface)` to `partial` (enabler event
correlated to an in-scope change).

**Group-membership change events are ingested on the same basis (decided):**
adding a service account or user to a group that holds a privileged role is the
indirect-escalation precursor (the Solorigate pivot) — an enabler of changes to
the three surfaces. The group-membership-change audit event family
(`google.admin.directory.member.insert` / `.delete`, and the Cloud IAM
group-membership equivalents) is ingested as `log_entries` for correlation only,
exactly like SA-key events: it feeds `correlate_by_actor` /
`cross_project_timeline` and enriches a subsequent in-scope change by a newly
privileged member. No group *state* enumeration, no managed surface. This
reclassifies the indirect `T1098.003` path from `out-of-scope (no group surface)`
to `partial`.

Enabler events ingested as correlation context (not managed surfaces, no state
loaders): **SA-key create/delete/upload** and **group member add/remove**.
Everything else is still ignored if present — storage, compute instances,
logging sinks, and all other resource types.

## Google-published shapes the loaders accept

Each loader parses the native Google shape and emits the SAME dataclass it emits
today (`IamPolicy`, `VpcFirewallRule`, `NetworkFirewallPolicy`, `Change`), so
everything downstream is untouched.

**IAM allow policies** — current state (`getIamPolicy` / Cloud Asset Inventory):
```
{ "version": 3, "etag": "...", "bindings": [
    { "role": "roles/owner", "members": ["user:a@x", "serviceAccount:s@p.iam.gserviceaccount.com"],
      "condition": { "title": "...", "expression": "..." } } ] }
```
Attached to a resource named `projects/X`, `folders/N`, or `organizations/N`.
Accept both the bare policy object and the Asset-Inventory wrapper
(`{ name: "//cloudresourcemanager.googleapis.com/projects/X", asset_type, iam_policy: {…} }`),
taking `resource` from the asset name. Member prefixes
(`user:`, `serviceAccount:`, `group:`, `domain:`, `allUsers`, `allAuthenticatedUsers`,
`principalSet:`) preserved verbatim; `condition` carried in `raw`.

**IAM changes** — Cloud Audit Log `SetIamPolicy` entries. The delta is published at
`protoPayload.serviceData.policyDelta.bindingDeltas`:
```
[ { "action": "ADD" | "REMOVE", "role": "roles/owner", "member": "user:a@x" } ]
```
This IS the before/after — a grant (`ADD`) becomes a `Change` with the member
absent in `before` and present in `after`; a revoke (`REMOVE`) the reverse.
(`protoPayload.metadata` is checked as a fallback location.)

**VPC firewall rules** — current state (`compute#firewall`):
```
{ "kind": "compute#firewall", "name", "network", "direction": "INGRESS|EGRESS",
  "priority": 1000, "sourceRanges": [...], "destinationRanges": [...],
  "allowed": [{ "IPProtocol": "tcp", "ports": ["22"] }], "denied": [...],
  "disabled": false, "logConfig": { "enable": true } }
```
`logConfig.enable` maps to `log_enabled`; the whole object kept in `raw`.

**Network firewall policies** — current state
(`compute#firewallPolicy`, global `networkFirewallPolicies` / regional
`regionNetworkFirewallPolicies`):
```
{ "kind": "compute#firewallPolicy", "name", "region"?, "rules": [
    { "priority", "direction", "action": "allow|deny|goto_next",
      "match": { "srcIpRanges": [...], "destIpRanges": [...],
                 "layer4Configs": [{ "ipProtocol": "tcp", "ports": [...] }] },
      "disabled", "enableLogging" } ] }
```
`region` absent → global; present → regional.

**Firewall / policy changes** — Cloud Audit Log method families
`v1.compute.firewalls.{insert,patch,delete}` and
`*.networkFirewallPolicies.{insert,patch,delete,addRule,patchRule,removeRule}`.
A single audit entry carries the new state in `protoPayload.request` but not the
prior state, so `before`/`after` for config changes is derived by
**snapshot diff** (`diff_policies`, already in the library) over two Asset
Inventory exports, OR — where only logs exist — `after` from the request with
`before` left empty (world-open / protection-removal detection still fires on
after-state, which is how `detect_firewall_exposure` already works).

## Cloud Audit Log envelope (the `LogEntry` shape)

Audit entries arrive as published `LogEntry` objects:
```
{ "protoPayload": { "@type": ".../AuditLog",
      "authenticationInfo": { "principalEmail": "..." },
      "requestMetadata": { "callerIp": "...", "callerSuppliedUserAgent": "..." },
      "serviceName": "...", "methodName": "SetIamPolicy",
      "resourceName": "projects/X", "serviceData" | "request" | "response": {...} },
  "insertId", "resource": { "type", "labels" },
  "timestamp", "severity", "logName", "receiveTimestamp" }
```
`logs.py` (`filter_log_entries`, `correlate_by_actor`, `correlate_changes_with_logs`)
keeps its current flat view; a new `flatten_log_entry(entry) -> dict` maps the
native nesting to that flat view, so `logs.py` is untouched. The flattener MUST
extract all of: `methodName` ← `protoPayload.methodName`, `principalEmail` ←
`protoPayload.authenticationInfo.principalEmail`, **`callerIp` ←
`protoPayload.requestMetadata.callerIp`** (required — `correlate_by_actor` keys on
it; omitting it silently blanks incident correlation), `resourceName` ←
`protoPayload.resourceName`, `timestamp` ← top-level `timestamp`. Only audit
entries whose `methodName` is in the three surfaces' method families are parsed;
others ignored.

## Change derivation — the crux (builder-check rulings)

The detectors impose a fixed contract on `Change`: IAM detection reads
`before/after` as `{"bindings": [{role, members}]}`; firewall world-open fires on
`after.sourceRanges` alone, but **priority-shadow, deny-rule delete, and
disable-of-deny all read `before`** — so a single audit log (after-state only)
cannot drive config detection. Resolved as:

- **Input shape (Q1):** keep a thin keyed container (the broker groups native
  records by surface — trivial bucketing, no field transform). Keys carry *current
  native state*: `iam_policies`, `vpc_firewall_rules`, `network_firewall_policies`;
  an optional prior snapshot under `*_prev`; `log_entries` = native `LogEntry`
  list; `resources` = inventory. Loaders keep their `data: dict` signatures and
  parse native records under their key. This is grouping, not the lossy
  field-normalization that was the original concern.
- **Config changes (firewall / network policy) — PRIMARY path (Q3):** derive via
  `diff_policies(prev_state, current_state)` (already in the library) over two
  native Asset-Inventory snapshots. Diffing yields real `before`/`after` and the
  `action` (CREATE/UPDATE/DELETE by key presence), so priority-shadow and
  deny-delete stay detectable. `diff_policies` sets `principal=""`; actor and
  `callerIp` are then attached by correlating each change with the native
  (flattened) audit logs via `correlate_changes_with_logs`. Logs-only (no prior
  snapshot) still catches world-open via after-state, but not shadow/delete —
  documented as a capability limit.
- **IAM changes (Q2):** two equivalent paths, both producing the bindings-dict
  contract. PRIMARY: `diff_policies` over prior+current IAM snapshots. ALT (when
  only logs exist): parse `SetIamPolicy` `policyDelta.bindingDeltas` into one
  `Change` per entry — `after.bindings` from `ADD` deltas, `before.bindings` from
  `REMOVE` deltas — which reproduces the detector's (role, member) grant diff
  exactly, with actor from `authenticationInfo.principalEmail`.
- **action mapping (Q3):** when deriving from a log `methodName`: `insert`→CREATE,
  `delete`→DELETE, `patch`/`*Rule`→UPDATE. When deriving from `diff_policies`:
  key-presence (new→CREATE, gone→DELETE, differ→UPDATE).

Net: the uniform primary mechanism is **two native state snapshots →
`diff_policies` → Changes, enriched with actor/IP from native audit logs**; the
`policyDelta` log path is the IAM-only fallback. This keeps all six benchmark
campaigns detectable.

### REVISED (supersedes the snapshot-primary ruling above): logs-primary via replay

The audit-log stream for the requested window is itself the change record, so a
separate snapshot pipeline is not required. `fetch` already pulls a window
(`start`/`end`); "what changed in the last N days" = fetch N days of
Admin-Activity logs. `load_audit_changes` derives `Change` from the logs:

- **IAM:** self-contained — each `SetIamPolicy` entry's
  `policyDelta.bindingDeltas` gives before/after directly. No replay.
- **Firewall / network policy:** reconstruct `before` by **replaying the
  resource's own in-window history** — process entries in timestamp order per
  resource, carrying a running reconstructed state; the `before` of a change is
  the state left by that resource's previous `insert`/`patch`. `patch` requests
  are partial, so replay MERGES the request onto the running state rather than
  treating it as full state.
- **Baseline gaps are reported, not guessed (the explicit "call it out" case):**
  if a resource's first in-window event is a `patch`/`delete` with no prior
  in-window `insert`, its true `before` is unknown. Emit the `Change` with
  `before = None` and a reason (`"baseline predates window"`), and detectors that
  need `before` (priority-shadow, deny-delete, disable-of-deny) abstain-with-note
  for that resource instead of guessing. Widening the fetch window recovers more
  baselines. (A `delete` request carries only the resource name, so a deleted
  rule's prior contents are knowable only from a prior in-window event — same
  rule, same handling.)

Current-state exports become **optional**, used only for static exposure scoring
and blast-radius context — never for change before/after. `diff_policies` over
two snapshots remains a secondary mode for callers who have snapshots, but is no
longer required. Primary input = **audit logs for the window**; the broker/`fetch`
brings exactly the window asked for.

## What changes / what does not

Changes:
- `loaders.py` — parse native shapes (bare and Asset-Inventory-wrapped); add
  `flatten_log_entry`; `load_audit_changes` derives `Change` from `policyDelta`
  (IAM) and from request/snapshot-diff (firewall/policy); scope-filter to the
  three method families.
- `fetch.py` / broker contract — broker becomes a credentialed **pass-through**
  that returns native GCP; README broker section rewritten (no normalization
  contract to implement).
- Fixtures — regenerated to **Google-published shapes** (real `LogEntry`,
  `compute#firewall`, `getIamPolicy`/Asset-Inventory records), behavior-equivalent
  to today's attacks + decoys. `fixtures/incidents/*` and `fixtures/synthetic.json`
  reissued in native form; `generate.py` updated.
- Tests/examples — updated to the native fixtures.

Unchanged (the point of keeping the dataclasses as the internal boundary):
- All dataclasses (`IamPolicy`, `VpcFirewallRule`, `NetworkFirewallPolicy`,
  `Change`, `Finding`, …).
- Every detector, `scoring`, `redact`, `prioritize`, `analyze`, `attack_coverage`
  (catalog/signatures/report), and the Code Mode sandbox + MCP server.
- The security model: no credentials in the sandbox; broker still holds them.

## Testing / fidelity

- Build to **Google's published Cloud Audit Log / Compute / Resource Manager
  schemas** (no live GCP dependency; stdlib only).
- Add a loader conformance test: native-shape fixtures for each surface and
  method family load into the correct dataclasses and drive the detectors
  (a parse→detect round-trip per surface, like the spike already demonstrated).
- A real sanitized sample is optional; if provided later it pins fidelity, but
  the published schema is the authority for this build.

## Designer calls (not individually user-confirmed)

- **Native-only**: the normalized envelope is retired; loaders accept
  Google-published shapes only. Pre-release, so a breaking input change is
  acceptable and strictly improves fidelity.
- **Canonical sources**: current state from Asset Inventory / API-list native
  objects (bare or asset-wrapped); changes from Cloud Audit Logs, with
  before/after from `policyDelta` (IAM) and snapshot-diff (config).
- **Dataclasses stay the internal boundary**, so detectors/scoring/redaction/
  coverage are untouched; the refactor is contained to loaders + fetch +
  fixtures + their tests.
- Member prefixes, IAM `condition`, and full native objects preserved in `raw`
  for forward safety even though current detectors don't read them.

## Non-goals

- No live GCP client, no new telemetry types, no surfaces beyond the three.
- No multi-cloud; GCP published shapes only.
- No change to detection logic, the ATT&CK catalog, redaction, or the sandbox.

## Acceptance criteria

- Loaders parse Google-published shapes (bare and Asset-Inventory-wrapped) for
  all three surfaces + their audit-log method families into the existing
  dataclasses; unknown resource types/methods are ignored.
- `before`/`after` for IAM changes is derived from `policyDelta.bindingDeltas`;
  config-change before/after from snapshot diff (or after-only from request).
- Detectors, `analyze`, and `python -m attack_coverage.report` produce the same
  results on the native fixtures as they do today on the normalized ones (the
  six campaigns + decoys behave identically).
- Fixtures are Google-published-shaped; `python -m unittest` green; zero new
  dependencies; broker documented as a pass-through.
