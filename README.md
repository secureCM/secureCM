# GCP Policy Analyzer

A pure-Python library for security teams that need ranked, redacted answers to GCP IAM and firewall questions — including multi-step ones like "every change in the last 7 days that increased external exposure on production networks, joined to service accounts that already hold high-privilege roles."

---

## Quick start (under 5 minutes)

```bash
git clone <repo-url>
cd secureCM
python examples/what_changed_yesterday.py
python examples/seven_day_exposure.py
python -m unittest discover -s tests
```

No dependencies beyond the Python standard library. No install step needed.

---

## Function reference

All symbols below are re-exported from `gcp_policy_analyzer` and listed in `__all__`.

### Fetch (pass-through broker client)

The broker is a credentialed **pass-through**: it holds the read-only GCP credential, fetches the requested window, and returns native JSON verbatim. It performs **no normalization**. The loaders (below) are the normalizer.

```
fetch_export(base_url, resource_type, scope, *, start=None, end=None, timeout=30) -> dict
```
GET `{base_url}/export?type=…&scope=…[&start=…&end=…]`, follows pagination via `nextPageToken`. Returns the merged envelope dict. Raises `BrokerError` on non-200, bad JSON, or pagination overflow.

```
fetch_all(base_url, scope, *, timeout=30) -> dict
```
Calls `fetch_export` for all four resource types (`iam_policies`, `vpc_firewall_rules`, `network_firewall_policies`, `log_entries`) and merges results into one envelope.

```
BrokerError
```
Exception class raised by fetch functions.

### Loaders

```
load_iam_policies(data: dict) -> list[IamPolicy]
load_vpc_firewall_rules(data: dict) -> list[VpcFirewallRule]
load_network_firewall_policies(data: dict) -> list[NetworkFirewallPolicy]
load_audit_changes(data, resource_types=None, start=None, end=None) -> list[Change]
```
Each loader reads its key from the envelope dict and returns typed dataclasses. `load_audit_changes` derives `Change` records from native `log_entries` (logs-primary derivation — see below); the old `audit_changes` pre-extracted key is no longer supported.

### Diff (two-snapshot comparison)

```
diff_policies(old: list, new: list, resource_type: str) -> list[Change]
```
Compares two point-in-time snapshots (same format as the loader inputs). Produces the same `Change` records as `load_audit_changes`; all downstream helpers work with either source.

```
Change  # dataclass
```
Fields: `resource`, `resource_type`, `action` (`CREATE`/`UPDATE`/`DELETE`), `before`, `after`, `timestamp` (UTC-aware), `principal`, `risk_delta`, `labels`.

### Scoring

```
score_rule_exposure(rule) -> ExposureScore
```
ExposureScore: `score` (int), `flags` (list[str]).

Scores a firewall rule on: open-to-world source ranges (+40), all ports (+20), logging disabled (+10), priority < 1000 (+10), broad protocol (+20).

```
score_iam_binding(binding, *, high_privilege_roles=None, toxic_combinations=None) -> RiskScore
```
RiskScore: `is_high_privilege` (bool), `service_account_member` (bool), `toxic_combination` (bool), `score` (int, sum of fired flag weights: +30 high_privilege, +10 service_account_member, +40 toxic_combination), `flags` (list[str] of fired flag names).

Defaults: `HIGH_PRIVILEGE_ROLES` = `{roles/owner, roles/editor, roles/iam.securityAdmin, roles/iam.serviceAccountTokenCreator, roles/iam.serviceAccountKeyAdmin}`; `TOXIC_COMBINATIONS` = `{roles/iam.serviceAccountTokenCreator, roles/iam.serviceAccountKeyAdmin, roles/iam.securityAdmin}`. Pass keyword args to override.

```
classify_change(change) -> ChangeClass
```
Returns one of: `BroadenedAccess`, `RemovedProtection`, `ShadowCreated`, `LeastPrivilegeImproved`, `Neutral`, `Other`. `ChangeClass` is importable for comparisons: `from gcp_policy_analyzer import ChangeClass`.

### Prioritize

```
prioritize_changes(changes: list[Change], context=None) -> list[PrioritizedChange]
```
PrioritizedChange: `rank` (int), `change` (Change), `change_class` (ChangeClass), `blast_radius` (BlastRadius). BlastRadius: `affected_resources` (int), `external_exposure` (bool), `production` (bool), `score` (int).

Filters out `Neutral`/`Other`, computes blast radius, sorts by `(blast_radius.score DESC, risk_delta DESC, timestamp DESC)`, assigns sequential `rank` values.

```
compute_blast_radius(change, context=None) -> BlastRadius
```
Returns `BlastRadius(affected_resources, external_exposure, production, score)`. Score formula: `affected_resources × (2 if external_exposure) × (2 if production)`. Pass `context` dict (same shape as the envelope, including `resources` list) to count real affected resources; defaults to 1 otherwise.

### Logs

```
filter_log_entries(entries, *, principal=None, methods=None, start=None, end=None) -> list
```
Filters raw log entry dicts by principal email, method names, and time window.

```
correlate_changes_with_logs(changes, entries) -> list[{"change": Change, "evidence": [...]}]
```
Attaches log entries to each change by matching `principalEmail`, resource path suffix, and timestamp within 300 seconds.

### Redact

```
redact_sensitive(obj, *, patterns=None, salt=None) -> dict | list
```
Recursively walks `obj` (dict, list, dataclass, string). Rules: SA emails → `sa-{6-char hash}@domain`; paths with 4+ `/` segments → `.../last/two`; strings matching `SECRET_PATTERNS` → `[REDACTED]`. Pure function; returns a copy. By default deterministic (same input → same mask, no salt) so the model can join the same account across results. Pass `salt=` for a per-run random salt that prevents cross-run joins — use this at hard trust boundaries.

```
register_redactor(fn) -> fn
```
Decorator that registers a custom `(obj) -> obj` redactor. Custom redactors run after built-ins on every `redact_sensitive` call, including inside `analyze()` and `format_report()`.

### Helpers

```
is_production(obj, *, label_keys=None, label_values=None) -> bool
```
Returns `True` only if `obj` carries a label whose key is in `label_keys` (default: `env`, `environment`) and value is in `label_values` (default: `prod`, `production`). No name-pattern guessing. **Label your production resources or this returns False.**

```
is_service_account(member: str | dict) -> bool
```
True if `member` (string or dict with `member` key) ends with `.gserviceaccount.com` after stripping any `serviceAccount:`/`user:`/`group:` prefix.

```
format_report(prioritized, all_changes=None) -> dict
```
Builds `{"summary", "prioritized", "stats"}` and calls `redact_sensitive` internally. Accepts an optional `all_changes` list to compute accurate `total_changes` and `neutral` stats.

### Top-level one-call path

```
analyze(data: dict, start: datetime, end: datetime, resource_types=None) -> dict
```
Load → prioritize → format → redact in one call. Returns `{"summary": str, "prioritized": [...], "stats": {...}}`. Already redacted; safe to return directly to a model.

---

## Examples

### `what_changed_yesterday.py`

```bash
python examples/what_changed_yesterday.py
```

Calls `analyze()` on the synthetic fixture for the 24-hour window ending 2026-10-31. Changes are derived via logs-primary: the 6 log entries in the window produce 6 `Change` records (CREATE+UPDATE for `prod-allow-tcp-8080`, CREATE+DELETE for `prod-deny-all-egress`, IAM `SetIamPolicy` is outside the 24h window, plus two description-only changes by alice). Two of those are risky.

Expected output shape:

```json
{
  "summary": "2 risky change(s) out of 6 total in window 2026-10-30 to 2026-10-31.",
  "prioritized": [
    {
      "rank": 1,
      "resource": ".../firewalls/prod-allow-tcp-8080",
      "action": "UPDATE",
      "principal": "sa-8ac9c3@example-prod-project.iam.gserviceaccount.com",
      "change_class": "BroadenedAccess",
      "blast_radius": {
        "affected_resources": 14,
        "external_exposure": true,
        "production": true,
        "score": 56
      },
      "risk_delta": 0,
      "timestamp": "2026-10-30T16:22:41+00:00"
    },
    {
      "rank": 2,
      "resource": ".../firewalls/prod-deny-all-egress",
      "action": "DELETE",
      "principal": "sa-8ac9c3@example-prod-project.iam.gserviceaccount.com",
      "change_class": "RemovedProtection",
      "blast_radius": {
        "affected_resources": 14,
        "external_exposure": false,
        "production": true,
        "score": 28
      },
      "risk_delta": 0,
      "timestamp": "2026-10-30T16:23:05+00:00"
    }
  ],
  "stats": {
    "total_changes": 6,
    "risky": 2,
    "neutral": 4,
    "principals": [
      "sa-8ac9c3@example-prod-project.iam.gserviceaccount.com",
      "alice@example.com"
    ]
  }
}
```

No raw service-account emails appear. The principal `terraform-deployer@…` is masked to `sa-8ac9c3@…` deterministically.

### `seven_day_exposure.py`

```bash
python examples/seven_day_exposure.py
```

Multi-step pipeline over a 7-day window. Expected output shape:

```json
[
  {
    "resource": ".../firewalls/prod-allow-tcp-8080",
    "action": "UPDATE",
    "principal": "sa-8ac9c3@example-prod-project.iam.gserviceaccount.com",
    "change_class": "BroadenedAccess",
    "timestamp": "2026-10-30T16:22:41+00:00",
    "blast_radius": {
      "affected_resources": 14,
      "external_exposure": true,
      "production": true,
      "score": 56
    },
    "risk_delta": 0
  },
  {
    "resource": ".../firewalls/prod-deny-all-egress",
    "action": "DELETE",
    "principal": "sa-8ac9c3@example-prod-project.iam.gserviceaccount.com",
    "change_class": "RemovedProtection",
    "timestamp": "2026-10-30T16:23:05+00:00",
    "blast_radius": {
      "affected_resources": 14,
      "external_exposure": false,
      "production": true,
      "score": 28
    },
    "risk_delta": 0
  }
]
```

---

## How a model should use this

`seven_day_exposure.py` is the canonical composition pattern:

```python
# 1. fetch or load  (broker returns native GCP JSON verbatim — no normalization)
with open("fixtures/synthetic.json") as f:
    data = json.load(f)
# or: data = fetch_all(broker_url, "projects/my-project")
# fetch_all fetches log_entries, iam_policies, vpc_firewall_rules, network_firewall_policies

# 2. load changes in window
changes = load_audit_changes(data, start=start, end=end)

# 3. filter — classify and production check
RISKY = {ChangeClass.BroadenedAccess, ChangeClass.RemovedProtection}
risky = [c for c in changes if classify_change(c) in RISKY and is_production(c)]

# 4. join — build high-priv SA set from IAM policies
policies = load_iam_policies(data)
high_priv_sas = set()
for policy in policies:
    for binding in policy.bindings:
        risk = score_iam_binding(binding)
        if risk.is_high_privilege:
            for member in binding.members:
                email = member.removeprefix("serviceAccount:")
                if is_service_account(email):
                    high_priv_sas.add(email)

# 5. keep only changes by high-priv SAs
hits = [c for c in risky if c.principal in high_priv_sas]

# 6. compute blast radius, sort descending
hits.sort(key=lambda c: compute_blast_radius(c).score, reverse=True)

# 7. redact before returning to model
output = [{"resource": c.resource, "principal": c.principal, ...} for c in hits]
print(json.dumps(redact_sensitive(output), indent=2))
```

The model writes the script; `run_script` executes it; `redact_sensitive` is the exit filter before output re-enters model context. Everything returned to a model must pass through `redact_sensitive`.

---

## Input model: native Google-published GCP

All input is **native Google-published GCP JSON** — no custom normalized envelope. The broker returns what the GCP APIs return; the loaders normalise it internally.

### Scope: three managed surfaces

| Surface | Key in envelope | Google schema |
|---------|----------------|---------------|
| IAM allow policies (project / folder / org) | `iam_policies` | Cloud Asset Inventory `getIamPolicy` / IAM policy resource |
| VPC firewall rules | `vpc_firewall_rules` | `compute#firewall` ([Compute Firewall](https://cloud.google.com/compute/docs/reference/rest/v1/firewalls)) |
| Network firewall policies (global + regional) | `network_firewall_policies` | `compute#firewallPolicy` ([Network Firewall Policies](https://cloud.google.com/compute/docs/reference/rest/v1/networkFirewallPolicies)) |

SA-key and group-membership events are ingested as **correlation context only** (enabler events: key-mint / group-add that precede an in-scope change, surfaced via `enrich_with_enablers`). They are never managed surfaces.

### Envelope keys

```json
{
  "iam_policies":              [...],
  "vpc_firewall_rules":        [...],
  "network_firewall_policies": [...],
  "log_entries":               [...]
}
```

`log_entries` is required for change derivation. Current-state keys (`iam_policies`, `vpc_firewall_rules`, `network_firewall_policies`) are optional — used for static exposure scoring and blast-radius context only.

### `iam_policies`

Native Cloud Asset Inventory asset-wrapped shape:

```json
{
  "name":       "//cloudresourcemanager.googleapis.com/projects/example-prod-project",
  "asset_type": "cloudresourcemanager.googleapis.com/Project",
  "iam_policy": {
    "bindings": [
      {
        "role":    "roles/editor",
        "members": ["serviceAccount:terraform-deployer@example-prod-project.iam.gserviceaccount.com"]
      }
    ]
  }
}
```

The loader also accepts a bare `getIamPolicy` response `{bindings:[…]}` and the legacy normalized shape `{resource, bindings, labels}`.

- `name`: `//service/…` Asset Inventory name; the loader strips the `//service/` prefix to a `projects/X` resource path.
- `iam_policy.bindings[].role`: GCP IAM role string
- `iam_policy.bindings[].members`: list of member strings with prefix (`serviceAccount:`, `user:`, `group:`)
- `labels`: key-value labels on the resource (used by `is_production`); may also appear at top level in the bare shape.

### `vpc_firewall_rules`

Native `compute#firewall` shape:

```json
{
  "kind":         "compute#firewall",
  "name":         "prod-allow-tcp-8080",
  "network":      "projects/example-prod-project/global/networks/prod-network",
  "direction":    "INGRESS",
  "priority":     1000,
  "sourceRanges": ["0.0.0.0/0"],
  "allowed":      [{"IPProtocol": "tcp", "ports": ["8080"]}],
  "denied":       [],
  "disabled":     false,
  "logConfig":    {"enable": false},
  "labels":       {"env": "prod"}
}
```

`sourceRanges` is an empty list for EGRESS rules. `allowed` and `denied` are mutually exclusive. `logConfig.enable` is the preferred field; the loader also accepts `log_enabled` as a fallback. The loader also accepts Cloud Asset Inventory asset-wrapped shape.

### `network_firewall_policies`

Native `compute#firewallPolicy` shape:

```json
{
  "kind":   "compute#firewallPolicy",
  "name":   "prod-network-policy",
  "region": null,
  "rules": [
    {
      "priority":  1000,
      "direction": "INGRESS",
      "action":    "allow",
      "match":     {"srcIpRanges": ["10.0.0.0/8"]}
    }
  ]
}
```

`region` present → regional policy (e.g. `"region": "us-central1"`); absent or `null` → global (`None` in the dataclass). Follows the `compute#firewallPolicy` shape for both global and regional policies.

### `log_entries` — Cloud Audit LogEntry (native)

Native Cloud Audit Log `LogEntry` shape with `protoPayload` of type `AuditLog`:

```json
{
  "timestamp": "2026-10-30T16:22:41Z",
  "protoPayload": {
    "methodName":  "compute.firewalls.patch",
    "resourceName": "projects/example-prod-project/global/firewalls/prod-allow-tcp-8080",
    "authenticationInfo": {"principalEmail": "terraform-deployer@example-prod-project.iam.gserviceaccount.com"},
    "requestMetadata": {"callerIp": "203.0.113.10"},
    "serviceData": {},
    "request": {"sourceRanges": ["0.0.0.0/0"]}
  }
}
```

Used by `load_log_entries` (flattens to a dict), `filter_log_entries`, and `correlate_changes_with_logs`. Flat dicts (already-extracted `methodName`, `principalEmail`, etc. at top level) are also accepted by `load_log_entries`.

### Change derivation: logs-primary

`load_audit_changes` derives `Change` records directly from `log_entries` — no pre-extracted `audit_changes` key:

- **IAM changes**: from `SetIamPolicy` entries via `serviceData.policyDelta.bindingDeltas`. Each ADD/REMOVE delta produces `before`/`after` bindings on the `Change`.
- **Firewall / network-policy changes**: by in-window replay of the resource's own audit history (sorted by timestamp). Each `insert` / `patch` / `delete` (and NFP `addRule` / `patchRule` / `removeRule`) advances the reconstructed state and emits a `Change`.

**Baseline-gap behaviour**: when a resource's prior state predates the fetched window, `running` starts as `None`. The emitted `Change` has `before=None` and carries `labels={"baseline": "predates_window"}`. Detectors that require a known `before` state abstain on these changes. To recover the baseline, widen the fetch window to include the resource's creation event.

**Enabler events** (`CreateServiceAccountKey`, `google.admin.directory.member.insert`, etc.) are loaded by `load_log_entries` but are not converted to `Change` records. They are correlation context only — surfaced by `enrich_with_enablers` to annotate in-scope changes.

### Broker HTTP contract

```
GET {base_url}/export?type={resource_type}&scope={scope}

  type  ∈ iam_policies | vpc_firewall_rules | network_firewall_policies | log_entries
  scope = projects/X | folders/N | organizations/N
  optional (log_entries only):
          &start={iso8601}&end={iso8601}

→ 200  application/json  native GCP JSON (verbatim, not normalized)
→ 4xx/5xx  any non-200 raises BrokerError in the library
```

The broker holds the read-only GCP credential. It fetches and returns native GCP JSON verbatim — **no normalization**. The sandbox sends no auth headers.

Pagination: if the response contains `"nextPageToken": "…"`, the library issues a follow-up request with `&pageToken={token}` appended. The broker must set `nextPageToken` in every intermediate page and omit it (or set it to `null`/`""`) on the final page.

Ceilings enforced by the library: `MAX_PAGES = 1000`, `MAX_RESPONSE_BYTES = 50 MB` per page. Exceeding either raises `BrokerError`.

---

## Secure execution

### Operator provisioning

Two data paths — both operator-controlled, both credential-free from the sandbox's perspective:

**Broker swap (live data):** The operator configures the broker (outside the sandbox) with a read-only GCP credential and the scopes it will serve. The sandbox calls the broker with plain HTTP — no auth headers. The LLM can name a scope in its script; it cannot grant one. Unconfigured scopes return an error from the broker.

**File (export/offline):** The operator exports data (`gcloud` output, Asset Inventory dump, log extract) and places the JSON file where the sandbox can read it. Scripts call `json.load(open(path))` and pass the result to the loaders. Examples and tests use this path.

The user asking the question never supplies credentials or raw log data through chat. They express intent only.

### Calling runtime responsibilities

The built-in `codemode/executor.py` is a reference implementation. A production deployment must also:

- **Sandbox the subprocess.** The executor launches a clean-environment subprocess; real isolation (namespace, seccomp, cgroups) is the external sandbox's responsibility.
- **Deny-by-default egress, broker allowlisted.** The sandbox should block all outbound network except the broker endpoint. The executor itself does not enforce egress.
- **No secrets in the sandbox.** GCP credentials, API keys, and tokens must never appear in the subprocess environment or working directory. The executor inherits no environment variables (`env={}` by design).
- **Log the exact code that ran.** `codemode/executor.py` writes every script verbatim to `codemode_audit.jsonl` before execution. This is an audit requirement; do not skip it.

### MCP quickstart

```bash
claude mcp add gcp-analyzer -- python codemode/mcp_server.py
```

The MCP server exposes two tools:

- **`describe_capabilities`** — returns the full function reference (signatures + docstrings) generated live from `gcp_policy_analyzer.__all__`. Call this first so the agent learns the API without any baked-in prompt context.
- **`run_script`** — takes a Python script string, executes it via the executor, returns redacted stdout. Accepts an optional `timeout` (seconds, default 60).

The server holds no LLM key and makes no model calls. The external agent (Claude Code, Agent SDK app, or any MCP client) writes the scripts; the server only runs them.

### Redaction posture

`redact_sensitive` is the mandatory exit filter. Every output path ends in it:

- `analyze()` calls it internally.
- `format_report()` calls it internally.
- Reference scripts call it explicitly before printing.

**Default (deterministic, no salt):** `sha256(email)[:6]` — same email always produces the same mask (`sa-8ac9c3@…`). The model can still correlate the same account across results. Resource paths with four or more `/` segments are shortened to `.../last/two`.

**Hard boundary (`salt=`):** Pass a per-run random string as `salt=` to produce an irreversible mask that changes every run. Use this when the model must not be able to join identities across separate analysis sessions.

**Custom rules (`@register_redactor`):**

```python
from gcp_policy_analyzer import register_redactor

@register_redactor
def mask_internal_ips(obj):
    if isinstance(obj, str) and obj.startswith("10."):
        return "[INTERNAL-IP]"
    return obj
```

Custom redactors run after the built-ins inside every `redact_sensitive` call, including calls made by `analyze()` and `format_report()`.

---

## Coverage

### ATT&CK catalog and report

The `attack_coverage` package ships a catalog of GCP-relevant MITRE ATT&CK techniques and a coverage report that maps each technique to the detectors that fire on it.

```bash
python -m attack_coverage.report
```

Prints a text matrix showing per-tactic coverage. To get the report programmatically:

```python
from attack_coverage.report import build_report
report = build_report()  # returns dict with keys: by_tactic, coverage, regressions, dangling, not_covered
```

The underlying technique catalog is in `attack_coverage/attack_catalog.json`.

### Scope: three surfaces

Coverage is limited to three control-plane surfaces that this library can observe:

- **IAM bindings** (`iam_policies` current state; `SetIamPolicy` entries in `log_entries`)
- **VPC firewall rules** (`vpc_firewall_rules` current state; `compute.firewalls.*` entries in `log_entries`)
- **Network firewall policies** (`network_firewall_policies` current state; `compute.networkFirewallPolicies.*` entries in `log_entries`)

### Why most of the ATT&CK matrix is out-of-scope

The library sees only GCP control-plane telemetry. Techniques that require endpoint telemetry (process, file, registry), network traffic analysis, EDR signals, or data-plane visibility (e.g., object storage access logs, runtime behavior) cannot be detected here. The out-of-scope techniques are marked in the catalog with a `surface_reason` explaining which telemetry source they require.

### In-scope techniques

| Technique | Name |
|-----------|------|
| T1098 | Account Manipulation |
| T1098.003 | Account Manipulation: Additional Cloud Roles |
| T1199 | Trusted Relationship |
| T1562 | Impair Defenses |
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall |
| T1485 | Data Destruction |
| T1580 | Cloud Infrastructure Discovery |
| T1069.003 | Permission Groups Discovery: Cloud Groups |
| T1078.004 | Valid Accounts: Cloud Accounts |

### Running all detectors in one call

```python
from attack_coverage.signatures import run_detectors
findings = run_detectors(envelope)   # envelope is the native GCP export dict (log_entries + optional current-state keys)
for f in findings:
    print(f.technique_id, f.technique_name, f.severity, f.resource)
```

Each `Finding` (importable from `gcp_policy_analyzer.detect`) has: `technique_id` (ATT&CK ID string), `technique_name` (human-readable name), `tactic` (ATT&CK tactic string), `severity` (`critical`/`high`/`medium`/`low`), `resource` (GCP resource path), `principal` (identity that triggered it), `timestamp` (UTC datetime or None), and `evidence` (dict of supporting data).

---

## Limitations

- **Detectors are stateless and high-recall.** Each detector evaluates a single event in isolation. Approved external grants, expected high-privilege service accounts, and changes that were reverted shortly after will all produce findings — the detector cannot distinguish benign-approved from malicious. Separating those cases requires an allowlist or behavioral-baseline layer that is out of scope for this release.

- **Heuristics are heuristics.** Scoring weights, `HIGH_PRIVILEGE_ROLES`, `TOXIC_COMBINATIONS`, and production label conventions ship as module-level constants and are intentionally overridable. The defaults are reasonable starting points, not ground truth. Override them by passing keyword arguments or editing the constants.

- **Blast radius is the simple version.** `compute_blast_radius` counts resources that share a network or project with the changed resource, multiplied by exposure and production flags. It is not a graph engine; it does not trace transitive dependencies, VPC peering, or cross-project bindings. The number is a prioritization signal, not a precise impact assessment.

- **Production detection is label-only.** `is_production` returns `True` only when the resource carries a label with key in `{env, environment}` and value in `{prod, production}`. There is no name-pattern guessing. If a resource is not labelled, this function returns `False` — and blast-radius scores, filtering, and the `seven_day_exposure.py` example will treat it as non-production. **Label your production resources.**

- **`diff_policies` description-only changes classify as `Other`, not `Neutral`.** When comparing two snapshots, `diff_policies` records carry full resource records in `before`/`after`; a description-only change produces a `Change` whose `before` and `after` each contain many fields beyond `description`, so `classify_change` sees a non-trivial diff and returns `Other`. The `Neutral` classification applies only to audit-log changes where `before`/`after` are the partial diffs stored in the audit record.
