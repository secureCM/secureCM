# ATT&CK Coverage System + Detection Helpers — Design

Date: 2026-10-31
Status: draft, pending approval
Builds on: 2026-10-31-gcp-policy-analyzer-design.md (the library) and the
`correlate_by_actor` quality work.

## Intent

Stop adding detections by imagination. Anchor the library's detection scope
to a fixed, versioned, externally-curated catalog of techniques observed in
the wild — the MITRE ATT&CK Cloud/IaaS matrix — and track, per technique,
whether we can detect it. "Where do we keep going?" then has a principled
answer: **we are done when every technique in the catalog is either
`covered` (with a detector and a passing fixture) or `out-of-scope` (with a
recorded reason).** The future is unknown; the known is finite; we build to
the known and measure the gap.

## Why ATT&CK as the system of record

- It *is* "attacks seen to date" — curated by a neutral body, versioned,
  and updated as new techniques are observed.
- Every public breach report decomposes into ATT&CK technique IDs, so a
  detector for a technique is reusable across every breach that uses it
  (e.g. T1562.008 covers both Imperva-2019 and DNSpionage-2019).
- It makes coverage a measurable fraction instead of a claim.

## Scope (decided)

- **GCP only.** The library stays GCP-shaped (resource paths,
  `*.iam.gserviceaccount.com`, `compute#firewall`). ATT&CK Cloud/IaaS is
  cloud-agnostic, so the catalog transfers to AWS/Azure later behind a
  normalization layer — a separate future effort, not this one.
- **Three config surfaces only:** IAM allow policies (project/folder/org),
  VPC firewall rules, and network firewall policies (global/regional) —
  plus the audit-change and API-log trail that evidences changes to those
  three. This matches the original approved library brief and leaves the
  approved library design UNCHANGED (no new envelope keys, no broker-
  contract change).

## Data-model reality (what bounds `out-of-scope`)

The library ingests CONTROL-PLANE data for the three surfaces above only:
IAM allow policies, VPC/network firewall rules, the audit-change records and
API log entries (methodName, principalEmail, callerIp, resourceName,
timestamp) that pertain to them, and the resource inventory for blast
radius. It does NOT ingest cloud storage, compute instances, service-account
keys, logging-sink/audit config, group-membership data, nor any
endpoint/process, DNS, netflow, email, or auth-event telemetry. Techniques
that require any of those are `out-of-scope` by data-surface — recorded with
that reason, not silently missing.

## The coverage ledger

A single versioned file, `coverage/attack_catalog.yaml`, is the source of
truth. One entry per ATT&CK technique/sub-technique in the Cloud/IaaS
matrix:

```yaml
- id: T1562.008
  name: Impair Defenses — Disable Cloud Logs
  tactic: Defense Evasion
  seen_in: [Imperva-2019, DNSpionage-2019]
  status: covered            # covered | partial | not-covered | out-of-scope
  signal: "logging_sink change with after.disabled == true"
  detector: detect_impair_defenses      # helper that flags it (null if none)
  fixture: incident_impair_defenses      # synthetic case that exercises it
  verified: 2026-10-31                   # date the test last proved it fires
  reason: null                           # required when out-of-scope
```

**Status taxonomy (the honesty mechanism):**
- `covered` — a detector flags it AND a fixture proves the detector fires.
- `partial` — detectable in principle from our data but the signal is weak
  or the detector catches only some variants; documented in `signal`.
- `not-covered` — detectable from our data model, no detector yet (this is
  the work queue).
- `out-of-scope` — not detectable from control-plane data; `reason`
  required (e.g. "requires process execution telemetry").

**Coverage metric:** `covered / (total − out-of-scope)`, reported per tactic
and overall. `out-of-scope` never counts against us, but each one is
visible and justified.

## Catalog seed (full Cloud/IaaS matrix, initial status vs. the three surfaces)

The catalog ships populated for the whole matrix; the three-surface scope
makes most of it honestly `out-of-scope`. Initial triage (exact IDs
finalized against the ATT&CK version pinned in the catalog header):

- **In scope — target `covered`/`partial` (IAM + firewall/network only):**
  Account Manipulation: Additional Cloud Roles, DIRECT grants (T1098.003) ·
  high-privilege / owner grants to external identities & Trusted
  Relationship (T1098, T1199) · toxic role combinations · Impair Defenses:
  Disable/Modify Cloud Firewall (T1562.007 — removing deny rules, disabling
  rules) · firewall/network exposure to `0.0.0.0/0` and broad
  protocols/ports (the exposure-scoring path) · Data Destruction limited to
  firewall/policy deletion (T1485, partial — only these surfaces) ·
  Discovery of IAM/firewall config via list/get bursts in logs (T1580,
  T1069 — partial) · Valid Accounts: Cloud (T1078.004, partial — a known
  principal acting anomalously against these surfaces, e.g. off an external
  or rotating IP).

- **`out-of-scope` by data-surface (NOT neglect) — reason recorded:**
  Data from Cloud Storage (T1530) & Transfer to Cloud Account (T1537) — no
  storage surface · Resource Hijacking (T1496) & Modify Cloud Compute
  (T1578.*) — no compute surface · Disable Cloud Logs (T1562.008) — no
  logging-sink surface · Additional Cloud Credentials / SA keys (T1098.001),
  App Access Token (T1550.001) — no key surface · INDIRECT group escalation
  (T1098.003 via groups), Cloud Groups discovery (T1069.003) — no
  group-membership surface · Cloud Instance Metadata (T1552.005) — no
  instance/metadata surface.

- **`out-of-scope` by telemetry (no such feed at all):**
  Phishing (T1566), MFA Request Generation (T1621), Command/Scripting &
  User Execution (T1059, T1204), Exploit Public-Facing App (T1190), Brute
  Force (T1110), Data Encrypted for Impact (T1486).

The plan's job is to move the first bullet to `covered`/`partial` with
fixtures; the second and third bullets stay `out-of-scope` with their
reasons, and that is a correct terminal state, not a gap.

## Detection helpers (what moves the needle)

Each helper is a pure function over the loaded envelope, returns structured
findings, and is exercised by the fixture(s) for the technique(s) it
detects. Scoped to the three surfaces (helpers that needed storage, compute,
logging-sink, or group data are dropped — those techniques are
`out-of-scope`):

- `correlate_by_actor(..., subnet_bits=24)` — extend the existing helper to
  group caller IPs by subnet, not just exact match (rotating-IP campaigns
  acting against IAM/firewall). Additive: keeps the existing exact-IP
  `shared_ips`/`anomalous_ips`; adds `shared_subnets`/`anomalous_subnets`.
- `cross_project_timeline(changes, logs) -> list` — order one principal's
  IAM/firewall activity across projects into a single sequence (the
  "no multi-project coordination" blind spot), over the in-scope surfaces.
- `detect_firewall_exposure(rules, changes) -> list` — world-open ingress,
  broad ports/protocols, removed/disabled deny rules; names T1562.007 and
  the exposure findings (wraps the existing exposure scoring).
- `detect_privilege_grant(iam_policies, changes) -> list` — high-privilege
  / owner grants, grants to external identities, toxic combinations; names
  T1098 / T1199 (wraps `score_iam_binding`). DIRECT grants only — indirect
  group escalation is out-of-scope.
- A small **signature pack** (`coverage/signatures.py`) mapping concrete
  IAM/firewall conditions to technique IDs, so findings are *named* with
  their ATT&CK ID instead of lumped — this is what lets a small model
  separate campaigns.

Dropped from the earlier draft (operate on out-of-scope surfaces):
`resolve_effective_roles` (groups), `detect_exfil` (storage),
`detect_resource_hijacking` (compute), `detect_impair_defenses`
logging-sink portion (keeps only the firewall-protection-removal portion,
folded into `detect_firewall_exposure`).

## Fixtures generated from the catalog

Synthetic incidents live under `fixtures/incidents/`, each tagged with the
in-scope technique IDs it exercises. A seeded generator builds them
deterministically.

**The integration fixture is IN-SCOPE ONLY (decided) — complex and large,
but every event is an IAM allow-policy, VPC-firewall, or network-policy
change (or its audit/log trail). No storage, compute, logging-sink, SA-key,
or group events appear in it.** Target shape: ~10 projects under a
folder/org hierarchy, 40+ day window, several thousand IAM/firewall changes
of routine noise, carrying multiple distinct in-scope campaigns with
different signatures, e.g.:
- folder/org-level role grant to an external identity that cascades to
  child projects (T1098.003, direct);
- firewall exposure campaign — world-open ingress on admin ports across
  several prod projects from rotating IPs (T1562.007 + exposure);
- defense-evasion by priority-shadowing a deny-egress rule rather than
  deleting it (T1562.007);
- trusted-relationship abuse — editor/owner granted to an external partner
  domain across projects (T1199);
- direct token-creator / owner binding to an SA at folder scope (T1098) —
  the dangerous grant is visible even though the subsequent impersonation
  (key/token telemetry) is out-of-scope.
Plus in-scope decoys that must NOT be flagged (approved external viewer,
dev firewall opened then reverted, expected staging owner-SA, a benign
internal-range firewall widen).

Rule: no technique may be marked `covered` without a fixture that exercises
its detector, and no fixture exists that isn't referenced by a catalog
entry — one source of truth, both directions.

## Coverage report

`python -m coverage_report` (stdlib) reads `attack_catalog.yaml`, runs each
`covered`/`partial` technique's detector against its fixture, and emits:
- a tactic-by-tactic matrix with per-tactic and overall coverage %,
- the `not-covered` work queue (detectable, no detector yet),
- the `out-of-scope` list with reasons,
- any technique whose `verified` date is stale or whose detector no longer
  fires against its fixture (regression).
The report is also a test: CI fails if a `covered` technique's detector
stops firing, or if a catalog entry references a missing detector/fixture.

## describe_capabilities integration

`describe_capabilities` gains a one-line coverage summary and points the
agent at the signature pack, so a Code Mode agent can ask "which techniques
can I detect, and with which helper" — making the catalog usable at
analysis time, not just at build time.

## Non-goals

- Not a SIEM, not real-time, not alerting — still a batch library over an
  exported envelope.
- Not ingesting new telemetry types to chase `out-of-scope` techniques;
  that's a future data-model decision, recorded as the reason, not done
  here.
- Not reproducing exploits — fixtures are synthetic control-plane artifacts
  modeling the *observable effect* of each technique for detection testing.

## Acceptance criteria

- `coverage/attack_catalog.yaml` enumerates the full ATT&CK Cloud/IaaS
  matrix (version pinned in a header), every entry with a status; every
  `out-of-scope` has a reason; every `covered`/`partial` names a detector
  and a fixture.
- Every technique in the in-scope set (IAM + firewall/network) is `covered`
  or `partial` with a passing fixture — none left `not-covered` at ship.
  Out-of-scope-by-surface and out-of-scope-by-telemetry techniques remain
  `out-of-scope` with reasons; that is a correct terminal state.
- The coverage report runs (stdlib only), prints the matrix + metric, and
  fails on regression or dangling references.
- Re-running the in-scope (three-surface) integration fixture through the
  signature pack names each in-scope technique instance by ATT&CK ID and
  separates the distinct campaigns (measured against the prior run's
  lumping failure), while correctly clearing the in-scope decoys.
- Pure Python stdlib; `python -m unittest` green; zero new dependencies
  (YAML parsed with a tiny stdlib-only reader, or the catalog is JSON to
  avoid a yaml dep — builder's call, recorded).

## Left to the builder

- Exact ATT&CK version to pin and the precise ID list (finalize against the
  pinned version).
- Scoring/weights inside each detector (documented as defaults).
- Whether the catalog is YAML (needs a minimal stdlib parser) or JSON
  (no dep) — recommend JSON to hold the zero-dependency line.
- Fixture realism beyond the required technique coverage.

## Builder-check rulings (settled by the designer)

- **Data surface (Q1):** no new envelope keys. Group memberships, logging
  sinks, storage, compute, and SA keys are OUT of scope by the surface
  decision, so the approved 5-type envelope and broker contract are
  unchanged. This moots the builder-check's largest concern.
- **ATT&CK source (Q2):** the catalog is a hand-curated, checked-in JSON
  constant authored once against a pinned ATT&CK version (header records
  the version). No network fetch, no STIX generator — preserves
  offline/zero-dependency. Updating ATT&CK versions is a reviewable manual
  diff.
- **Baseline fixture (Q3):** the multi-project haystack generators built
  during testing live outside the repo (scratch). The plan promotes a
  cleaned, in-scope version into `fixtures/incidents/` as the integration
  fixture; incidents whose defining acts are out-of-scope surfaces are
  included precisely to assert the coverage report marks them
  `out-of-scope`, not missed. The recorded prior "lumping" run is the
  qualitative baseline.
- **`correlate_by_actor` subnet (Q4):** additive — default stays exact-IP;
  subnet grouping adds new output keys, never replaces, so the documented
  join-on-shared-IP contract and existing detectors/fixtures stand.

## Calls made by the designer

- GCP only; three config surfaces only (IAM allow policies, VPC firewall
  rules, network firewall policies) + their audit/log trail — per the scope
  decision; the approved library design is untouched.
- ATT&CK Cloud/IaaS as the catalog spine (vs. a home-grown taxonomy); most
  of the matrix is correctly `out-of-scope` under the three-surface scope.
- `out-of-scope` is a first-class status with a mandatory reason; coverage
  metric = `covered / (total − out-of-scope)`.
- Fixtures and detectors share the catalog as a single source of truth,
  enforced bidirectionally by the coverage report.
