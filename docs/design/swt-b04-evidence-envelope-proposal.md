# SWT-B04 design note: test evidence envelope and core release-evidence schema

Status: **PROPOSAL.** Six items of the core are frozen as 0.1.0 by [swt-core-0.1.0-freeze.md](swt-core-0.1.0-freeze.md); everything else in this note remains a proposal and is not frozen. Fields, names, versioning and acceptance criteria need an owner decision. Apple/Android profiles must pin core 0.1.0 and must not be promoted to 1.0.0 before the core is. The owner rulings recorded below (F1 to F7) shape this proposal; they do not freeze it.

## 1. Test evidence envelope (one entry of `tests[]`)

Owner ruling F1: the vocabulary of the experimental fixtures governs. The build identity lives in the record-level `artifact` and `source` groups, and each envelope is one entry of `tests[]` bound to that identity. The former `build.*` names are withdrawn.

| Field | Purpose | Threat addressed |
| --- | --- | --- |
| `artifact.digest`, `source.revision`, `source.dirty`, `tests[].artifactDigest` (must equal `artifact.digest`) | Bind a result to the exact build | Green run on a different build (T1) |
| `tests[].command`, `tests[].exitCode`, `tests[].startedAt`, `tests[].finishedAt` | What was run and when (automated branch) | Stale/copied results (T2); AI "tests pass" claims without a run (T9) |
| `tests[].environment.declared`, `tests[].environment.differencesFromProduction[]` | Fidelity statement | Environment drift (T11) |
| `tests[].result.summary`, `tests[].result.skipped[]`, `tests[].result.retries[]`, `tests[].result.quarantined[]` | Disclosed instability and scope reduction | Flaky retry-to-green (T4), silent skips (T6) |
| `tests[].evidenceKind` = `automated` or `manual` | Selects the per-kind branch; never upgraded into each other | Manual presented as automated |
| `tests[].retention.location`, `tests[].retention.hash` | Where the artifact lives | Unverifiable evidence |

Only `artifact.digest`, `source.dirty`, `tests[].artifactDigest`, `tests[].evidenceKind`, `tests[].command` and `tests[].exitCode` are exercised by the experimental fixtures; the other names are proposals not yet exercised.

**Per-kind branches (owner ruling F2).** There is one envelope with a branch per `evidenceKind`. Both branches require `evidenceKind` and the digest binding `tests[].artifactDigest`. The `automated` branch also requires `command` (non-empty) and `exitCode`; a non-zero exit code is not a pass. The `manual` branch does not carry `command` or `exitCode`, and a manual entry that carries either (in any form) is rejected; its remaining required fields (for example who performed the procedure and the procedure reference) are not yet defined. A manual result may never be labelled `automated`.

Surfaces: static, ingested, attested.

**Outcomes (owner ruling F4).** Evaluation yields `pass`, `reject` or `not-evaluated`. A present but invalid value always rejects. At stage `production` an absent required core field rejects. Below production an absent required core field yields `not-evaluated`, never `pass`. `pass` requires no errors and nothing not-evaluated.

## 2. Core release-evidence schema (`release-evidence`, semver)

Groups: artifact identity (`artifact`); `source`; build environment; `tests[]` (the envelopes above, plus links to run/not-run matrix cells); `testRuns[]` (reserved core name, see open points); `approvals` (identifiers only); `provenance`; `signing.status` (`not-evaluated | attested | ingested | failed`, fingerprints only); distribution `stage` (`internal | test | staged | production`) and `distribution`; `residualRisks[]` (owner, review date); `rollback` (method, tested, evidence ref). Owner ruling F6: core group names are plural where they hold lists (`residualRisks[]`, `testRuns[]`); the singular `residualRisk` is not a core name.

**Dirty source (owner ruling F3).** `source.dirty` is a required boolean at every stage. A dirty source (`true`) is invalid only at stage `production`.

Extension model: profiles (`apple/1`, `android/1`) pin an exact `coreVersion`, add fields only in their own namespace, and may not redefine core fields. Owner ruling F7: a profile namespace may not contain a core group name as a key at any depth, inside objects or arrays. Minor versions additive; breaking change requires a major bump. The core imports nothing; profiles never import each other. Distribution: vendored versioned copy with provenance header, hash and a drift conformance test (decision S19b).

## 3. Safety
Proposed requirement (not yet enforced by any schema): evidence fields must carry fingerprints and identifiers only. Free-text fields such as `tests[].command`, environment declarations, result summaries and retention locations are the likely carriers of credentials, so a future schema must restrict their content and a validator must reject recognisable secret patterns on ingestion. Pattern detection cannot guarantee absence of secrets; absence of a detected secret is not evidence of none.

## 4. Open items for the owner
Exact types of the fields not yet exercised; the required fields of the manual branch; retention minimums. Field naming of the exercised fields (F1), the envelope shape (F2), the dirty rule (F3) and the outcomes (F4) have owner rulings recorded above; the envelope shape, the dirty rule, the outcomes and the plural names are frozen as 0.1.0 by swt-core-0.1.0-freeze.md, and the rest is not frozen.

## Open points recorded after independent review (only the six items in swt-core-0.1.0-freeze.md are frozen)

- **Charter amendment needed (Standard 02).** Charter Standard 02 says manual and automated evidence "use separate schemas". Owner ruling F2 chose one envelope with per-kind branches. This proposal therefore depends on an amendment of the charter wording for Standard 02; that amendment has not been made and this note does not make it.
- **`tests` versus `testRuns`.** Owner ruling F1 keeps `tests[]` as the group that holds the envelopes. Owner ruling F6 names `testRuns[]` as a plural core name. The experimental checker keeps `tests` as the evaluated group and reserves `testRuns` (it is protected from profile redefinition, optional, and validated only as an array when present at the top level; its contents are not validated). Whether `testRuns[]` becomes a distinct group (for example the run/not-run matrix) or is dropped needs an owner decision before the core is promoted to 1.0.0; 0.1.0 freezes only the name and array type of `testRuns[]`.
- **Checker.** The experimental checker at `experimental/check-release-evidence.mjs` adds a pattern guard for secrets as defence in depth; it is not an enforced property of any schema, and a non-detection does not prove absence.
- **Not-evaluated in the checker.** The experimental checker implements the F4 outcomes through `evaluate(record)`. It evaluates only these: artifact digest; tests and their per-kind fields (including the rules that a manual entry carries no `command` or `exitCode` and that an optional `manual` flag must be a boolean); signing status; stage; the source dirty flag; a pattern-based secret scan (defence in depth only: a non-detection is not proof that no secret is present); and the rule that no core group name appears at any depth inside a profile namespace. Records that are too deep, too large, circular or not serialisable are rejected rather than causing an error. The secret scan accepts a value that is entirely a variable or secret reference (`$VAR`, `${VAR}`, `%VAR%`, or `${{ secrets.NAME }}`-style dotted identifiers) or a mask (`***`, `<redacted>`, `[redacted]`) as not a secret, with quotes that must pair and nothing attached; a literal shaped like a reference cannot be told apart from one. Its accepted limits are listed in the checker header. Approvals, rollback, provenance and distribution are not yet required or validated there, and the content of residual risks and test runs is not validated (only that a present top-level `residualRisks` or `testRuns` is an array).
- **Signing status `not-evaluated`.** A record whose `signing.status` is the declared value `not-evaluated` can still receive the verdict `pass`, because the field is present and valid. Whether a declared not-evaluated signing status should hold the overall verdict at `not-evaluated` (or reject at production) is an open owner question.
