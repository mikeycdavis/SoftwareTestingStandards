# SWT-B04 design note: test evidence envelope and core release-evidence schema

Status: **PROPOSAL, not frozen.** Fields, names, versioning and acceptance criteria need an owner decision. Apple/Android profiles must not freeze until this is frozen.

## 1. Test evidence envelope (per test run)

| Field | Purpose | Threat addressed |
| --- | --- | --- |
| `build.artifactDigest`, `build.sourceRevision`, `build.dirty` | Bind a result to the exact build | Green run on a different build (T1) |
| `run.command`, `run.exitCode`, `run.startedAt`, `run.finishedAt` | What was run and when | Stale/copied results (T2); AI "tests pass" claims without a run (T9) |
| `environment.declared`, `environment.differencesFromProduction[]` | Fidelity statement | Environment drift (T11) |
| `result.summary`, `result.skipped[]`, `result.retries[]`, `result.quarantined[]` | Disclosed instability and scope reduction | Flaky retry-to-green (T4), silent skips (T6) |
| `evidence.kind` = `automated` or `manual` | Never upgraded into each other | Manual presented as automated |
| `retention.location`, `retention.hash` | Where the artifact lives | Unverifiable evidence |

Surfaces: static, ingested, attested. A field absent from the evidence yields `not-evaluated`, never pass.

## 2. Core release-evidence schema (`release-evidence`, semver)

Groups: artifact identity; source; build environment; tests (links to envelopes, run/not-run matrix cells); approvals (identifiers only); provenance; `signing.status` (`not-evaluated | attested | ingested | failed`, fingerprints only); distribution stage; residual risks (owner, review date); rollback (method, tested, evidence ref).

Extension model: profiles (`apple/1`, `android/1`) pin an exact `coreVersion`, add fields only in their own namespace, and may not redefine core fields. Minor versions additive; breaking change requires a major bump. The core imports nothing; profiles never import each other. Distribution: vendored versioned copy with provenance header, hash and a drift conformance test (decision S19b).

## 3. Safety
Proposed requirement (not yet enforced; no guard exists in this repository): evidence fields must carry fingerprints and identifiers only. Free-text fields such as `run.command`, environment declarations, result summaries and retention locations are the likely carriers of credentials, so a future schema must restrict their content and a validator must reject recognisable secret patterns on ingestion. Pattern detection cannot guarantee absence of secrets; absence of a detected secret is not evidence of none.

## 4. Open items for the owner
Exact field names and types; whether `dirty` blocks release evidence; retention minimums. None decided here.

## Open points recorded after independent review (nothing here is frozen)

- **Charter tension.** Charter Standard 02 says manual and automated evidence "use separate schemas". This proposal uses one envelope with a discriminating `evidence.kind`. The two may be reconciled by per-kind schema branches inside one envelope, or the charter wording may change. This is an open owner question, not a decision.
- **Field names.** This table uses `build.artifactDigest`, `build.sourceRevision` and `build.dirty`. The experimental fixtures on the rejection-fixtures branch use `artifact.digest`, `source.dirty` and `tests[].evidenceKind`. The fixture round must be aligned to this table, or this table amended, before the core is frozen.
- **Checker.** The experimental checker on the fixtures branch adds a pattern guard for secrets; it is not an enforced property of any schema.
- **Absent-means-not-evaluated.** The rule above is the proposal intent. The experimental checker on the fixtures branch has no not-evaluated outcome: it rejects an absent or invalid checked field (artifact digest, tests, signing status, stage, source dirty flag), so it shows only that absence never passes. Approvals, residual risk, rollback, provenance and distribution are not yet required or validated there.
