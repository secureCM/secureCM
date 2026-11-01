# Letting models analyze GCP IAM and firewall changes via Code Mode

I wanted an agent to answer questions over bulky, sensitive GCP config and audit-log data without putting that data in the context window, and without the model's judgment being what decides whether a change is dangerous. This is what I built and what I measured.

## Mechanism

Two MCP tools: `describe_capabilities` returns the library's function list; `run_script` executes a Python script in a sandbox. The model calls the first, writes one script, and the script runs against the data inside the sandbox. Only a redacted result returns to the model.

The library is deterministic helpers: loaders for native GCP shapes, snapshot/log diffing, exposure and IAM-risk scoring, ATT&CK-tagged detectors (firewall exposure, privilege grant, discovery bursts, anomalous actor), per-actor correlation, and a redactor. The split is deliberate: the model decides *which* helpers to run and how to filter/rank; the library decides *what is dangerous*. Findings carry ATT&CK IDs (T1098, T1199, T1562.007, …). So the model's contribution is orchestration, and the security-relevant call is deterministic and reviewable.

Three properties that follow from the data-flow:

- The raw export (~1.9 MB of nested `LogEntry` JSON for 10 projects) never enters the context. The model manipulates it by reference. Service-account emails come back masked to a stable hash (`sa-a1447b@…`), so the model can correlate the same actor across events without seeing who it is.
- Changes are derived logs-primary: IAM from `SetIamPolicy` `policyDelta.bindingDeltas`; firewall/network-policy by replaying each resource's own in-window audit history. When a resource's prior state predates the window, `before` is reported as unknown rather than guessed, and detectors that need it abstain.
- The sandbox holds no credentials (a broker outside it attaches a read-only credential; egress is a single allowlisted endpoint), and the exact script the model ran is logged verbatim. A coverage catalog maps the GCP/IaaS ATT&CK matrix to detectors and fails CI if a detector stops firing or a catalog entry points at a missing detector/fixture.

## Benchmark

Same neutralized native-shaped fixture both ways — nested `protoPayload`/`policyDelta`, attack markers scrubbed so campaigns are found by behavior, not by grepping names. 10 projects, ~3,900 native audit-log entries, six buried campaigns, four decoys. Two models at low reasoning effort, 5 trials each, with and without the helpers:

| | Haiku + helpers | Haiku raw | Sonnet + helpers | Sonnet raw |
|---|---|---|---|---|
| Mean recall | 3.2/5 (64%) | 2.0/5 (40%) | 5.0/5 (100%) | 4.0/5 (80%) |
| Recall floor (worst run) | 2/5 | 1/5 | 5/5 | 4/5 |
| Zero-recall runs | 0 | 0 | 0 | 0 |
| False positives / run | 1.2 | 1.2 | 1.0 | 0.6 |
| Tokens / run | ~20k | ~28k | ~31k | ~28k |

What the numbers show:

- With Haiku, the helpers move mean recall 40% → 64%, raise the worst-case floor 1/5 → 2/5, and cut tokens (~28k → ~20k, because the sandbox returns compact findings instead of the model reading raw logs).
- With Sonnet, the helpers give 5/5 on every run — the detectors hand over the full set and a capable model stops discarding true findings.
- The helpers' edge narrows as the model improves (+60% relative recall at Haiku, +25% at Sonnet) but doesn't disappear. The one campaign raw reasoning missed on every Sonnet run was a priority-shadow on a deny-egress rule (raising a deny rule's priority so an allow wins) — a before-state reconstruction the library does and hand-analysis didn't.
- One decoy is a false positive for both approaches: a firewall opened to 0.0.0.0/0 and reverted two hours later, as two separate log entries. Neither correlates the pair; that needs temporal correlation I don't do yet.

Caveats: five trials is small; the remaining Haiku misses are mostly the model dismissing correct detector output, not detection failures; the reference executor is bare and assumes a real sandbox around it.

## The case it's for: multi-day chains

The target isn't a single loud event. A realistic cloud chain (TTPs modeled on Capital One and SolarWinds-style activity) looks like: day 0 a key is minted for a service account; day 3 that SA is added to a group holding `tokenCreator` at folder scope (no direct role grant to flag); day 7 it opens a prod firewall to 0.0.0.0/0; day 10 it priority-shadows a deny-egress rule. Four events, three principals, three data types, ten days. A person triaging the daily feed sees four unrelated, individually-plausible events a week apart and connects none of them.

The helpers connect them deterministically: windowed log replay ("what changed in the last N days"), per-actor correlation that flags a caller IP or subnet shared across different principals, a cross-project timeline, and enabler-event linking (the day-0 key mint to the day-7 abuse). In a separate needle test, one anomalous IP tying a key creation to a firewall change nine days apart across 400+ records reduced to a single function call. The connective tissue is the part that's deterministic, which is why a weaker model can still surface it.

## Limitations

Scope is three surfaces — IAM allow policies, VPC firewall rules, network firewall policies — plus SA-key and group-membership events as correlation context; everything else is explicitly out of scope and the catalog records it. No temporal-correlation layer yet (hence the reverted-firewall false positive). No alerting, no streaming — it's a batch library over an export, not a SIEM. The reference executor is minimal; production isolation (deny-by-default egress, real sandboxing) is the caller's responsibility. Five trials is directional, not definitive.

Fixtures, the ATT&CK coverage catalog, and the benchmark harness are in the repo.

Repo: [link]
