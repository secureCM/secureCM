# Keeping raw GCP logs out of the LLM context window with a two-tool Code Mode

The problem I kept hitting: to answer "did anything dangerous change in the last 7 days" over real GCP data, you either dump 1.9 MB of nested `LogEntry` JSON into the context window — which is expensive, leaks service-account emails, and asks the model to hold the whole IAM binding graph in working memory — or you write a bespoke script every time. Neither scales.

The alternative I tried: give the model two MCP tools and a pure-Python library running inside a sandbox. The model calls `describe_capabilities` to learn what functions exist, writes one script using them, and `run_script` runs it. Only the redacted result comes back. Raw logs stay inside the sandbox.

## How the split works

The library is deterministic helpers. The model is the orchestrator. Specifically:

- **Library decides what is dangerous.** Scoring functions (`score_rule_exposure`, `score_iam_binding`), detectors (`detect_firewall_exposure`, `detect_privilege_grant`, …), and the redactor are library code. Findings carry ATT&CK IDs. A security engineer can read and audit them.
- **Model decides what to ask.** It writes a short script that calls those functions, filters, joins, and ranks. The model contributes orchestration, not security judgment.
- **Redaction at the trust boundary.** Service-account emails come back as stable hashes (`terraform-deployer@…` → `sa-8ac9c3@…`). The hash is deterministic, so the model can still correlate the same actor across events. Human emails and caller IPs are unmasked. The boundary is `*.iam.gserviceaccount.com`.

Changes are derived logs-primary: IAM from `SetIamPolicy.policyDelta.bindingDeltas`, firewall rules by replaying each resource's own in-window audit history. When prior state predates the window, `before` is `None` and detectors that need it abstain — rather than guess.

## The benchmark

Same neutralized native-shaped fixture both ways. 10 projects, ~3,900 audit-log entries, five buried campaigns modeled on real-world attack patterns (Capital One-style S3/GCS exposure, SolarWinds-style trusted-relationship abuse, priority-shadow on a deny-egress rule, cross-project owner grant, SA key creation + later abuse). Attack markers scrubbed so campaigns are found by behavior, not by name-matching. Four decoys. Two models at low reasoning effort, 5 trials each:

| | Haiku + helpers | Haiku raw | Sonnet + helpers | Sonnet raw |
|---|---|---|---|---|
| Mean recall | 3.2 / 5 (64%) | 2.0 / 5 (40%) | 5.0 / 5 (100%) | 4.0 / 5 (80%) |
| Worst run | 2 / 5 | 1 / 5 | 5 / 5 | 4 / 5 |
| False positives / run | 1.2 | 1.2 | 1.0 | 0.6 |
| Tokens / run | ~20k | ~28k | ~31k | ~28k |

Three things stand out:

**Haiku gets a +24 pp lift and uses fewer tokens.** The sandbox returns compact findings instead of the model reading raw logs. Haiku misses were mostly the model dismissing correct detector output, not the detector missing the event. That's a different problem — the signal was there, the model chose not to act on it.

**Sonnet goes from 4/5 to 5/5.** The one campaign it consistently missed on raw data was the priority-shadow: a deny-egress rule's priority raised so an allow rule wins. Finding it requires reconstructing the before-state from a log replay. That's what the library does; the model without it didn't reconstruct it.

**The helpers don't increase false positives.** Both approaches produce roughly the same FP rate. The library is high-recall and intentionally so — a reverted firewall (opened and closed two hours later, two separate log entries) fires as a finding because temporal correlation of revert pairs isn't implemented. That's a known gap, not noise from the model hallucinating.

Five trials is directional. The result is consistent across runs but not a large-sample study.

## The case the library is for

The target isn't a single loud event. A realistic chain looks like: day 0, an SA key is minted; day 3, that SA is added to a group holding `tokenCreator` at folder scope; day 7, it opens a prod firewall to `0.0.0.0/0`; day 10, it priority-shadows a deny-egress rule. Four events, three principals, three data types, ten days. Someone triaging the daily Pub/Sub feed sees four individually-plausible operations a week apart and connects none of them.

The connective tissue is deterministic: windowed log replay, per-actor correlation that flags a caller IP shared across different principals, a cross-project timeline, and enabler-event linking (key mint to later abuse). In the needle test, one anomalous public IP tying a key creation to a firewall change nine days apart across 400+ log entries reduced to a single `correlate_by_actor` call. A Haiku-tier model found it.

## What it is and isn't

Three surfaces: IAM allow policies, VPC firewall rules, network firewall policies. SA-key and group-membership events as correlation context. Everything else is out of scope and the ATT&CK coverage catalog records it explicitly.

Not a SIEM. Not streaming. Batch over an export. The reference executor (`codemode/executor.py`) is minimal — real isolation (deny-by-default egress, namespace/seccomp, no credentials in the subprocess environment) is the operator's responsibility. The repo documents this and the quickstart won't let you miss it.

The split between `runtime/` (what goes in a sandbox) and `dev/` (examples, fixtures, tests) is deliberate. Copy `runtime/` into whatever sandboxing layer you already use.

Repo: https://github.com/secureCM/secureCM
