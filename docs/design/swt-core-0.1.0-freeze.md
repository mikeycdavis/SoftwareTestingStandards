# SWT release-evidence core 0.1.0: what is frozen

Status: **Initial freeze as 0.1.0, not 1.0.0.** Frozen by owner ruling F8 and the owner's instruction to freeze exactly the six items below. Promotion to 1.0.0 requires a consumer profile that passes conformance and a pinned real-adopter validation. No tag or release is made by this change.

Artifact: [`schemas/release-evidence.core.0.1.0.schema.json`](../../schemas/release-evidence.core.0.1.0.schema.json), with its recorded sha256 in `schemas/release-evidence.core.0.1.0.schema.json.sha256` (hash of the file with CRLF normalised to LF; `.gitattributes` keeps the schema LF). The drift test in `test/core-schema-conformance.test.mjs` detects a mismatch between the schema and its recorded hash (decision S19b: vendored versioned copy, hash, drift test). It does not stop someone editing both files: a change to a file named 0.1.0 is a reviewable diff and by policy needs a new version, but that is not enforced by the test. Consumers vendor the file with its hash.

## Frozen in 0.1.0

1. **The single envelope with per-kind branches.** One envelope, one entry of `tests[]`, with `evidenceKind` of `automated` or `manual`. Both branches require `evidenceKind` and `artifactDigest`. The `automated` branch requires `command` (non-blank string) and `exitCode` equal to `0`. The `manual` branch carries neither `command` nor `exitCode`. A `manual: true` entry may not be labelled `automated`; when present, `manual` is a boolean.
2. **`source.dirty`.** A boolean, required at every stage. `true` is invalid only at stage `production`.
3. **The `not-evaluated` outcome.** An absent required field below stage `production` is not-evaluated, never pass. At stage `production` it rejects. A present but invalid value always rejects. `pass` requires no errors and nothing not-evaluated. The set that is required at stage `production` is part of this item, and is therefore frozen with it: the `artifact` group with a non-blank `artifact.digest`; a non-empty `tests[]` (when `tests` is present at any stage it must be a non-empty array); the `signing` group with `signing.status`; `source` with `dirty`; and, per test, `evidenceKind` and `artifactDigest` plus the branch fields of item 1. The enums are frozen too: stage `internal`, `test`, `staged`, `production`; `signing.status` `not-evaluated`, `attested`, `ingested`, `failed`. These were the fields the owner-ruled fixtures already exercised; they are named here so the freeze claims nothing unstated.
4. **`residualRisks[]`.** The plural core name; when present at the top level it is an array.
5. **`testRuns[]`.** The plural core name; when present at the top level it is an array.
6. **The `evaluate()` result shape.** `{ verdict, errors, notEvaluated }` where `verdict` is `pass`, `reject` or `not-evaluated`, and `errors` and `notEvaluated` are arrays of strings. A non-object record is rejected with `record must be an object`.

What items 4 and 5 freeze is the name, the plural form and the array type. Nothing about the content of either array is defined or validated in 0.1.0, and the schema does not require them.

## Not frozen, still open

- Retention, approvals, rollback, provenance and distribution validation.
- The required fields of the manual branch (who performed the procedure, the procedure reference).
- The amendment of charter Standard 02, which says manual and automated evidence "use separate schemas", against ruling F2. The charter has not been amended by this change.
- Anything else not listed above, including `tests[]` fields other than those in item 1 (`startedAt`, `finishedAt`, `environment`, `result`, `retention`), `source.revision`, `artifact.id` and `schemaVersion`.
- The relationship between `tests[]` and `testRuns[]` (a distinct run/not-run group, or dropped). 0.1.0 freezes only the name and array type of `testRuns[]`.
- Whether a declared `signing.status` of `not-evaluated` should hold the overall verdict at not-evaluated. Today such a record can pass.
- The secret scan, the digest-equality rule between `artifact.digest` and `tests[].artifactDigest`, the record depth and size limits, and the profile-redefinition rule. These live in the experimental checker and are not part of the frozen schema; the scan is defence in depth, and a non-detection is not proof that no secret is present.
- Apple and Android release profiles: unblocked from waiting on this freeze, but each must pin `coreVersion` 0.1.0 and pass conformance before anything is promoted to 1.0.0.

## What the schema does and does not express

The schema describes present values. It cannot say "absent is not-evaluated"; that is the evaluator's contract (item 3). The conformance test requires, for every fixture, that the schema accepts the present values of each pass and not-evaluated fixture, and rejects each reject fixture whose reason is structural. Fixtures whose only reasons are evaluator-only rules (secret scan, digest equality, profile redefinition, record limits) are not compared against the schema.

## Change in this PR beyond the schema

The experimental checker now rejects a top-level `testRuns` or `residualRisks` that is present but not an array (items 4 and 5), with four new fixtures. Its header now points at this freeze.
