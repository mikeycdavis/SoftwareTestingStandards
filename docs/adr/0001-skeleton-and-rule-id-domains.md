# ADR 0001: Skeleton, vendored core provenance, rule-ID domains (SWT-B01)

Status: **Proposed.** Nothing here is frozen; acceptance criteria need an owner decision.

- Skeleton only: package.json, one test, this ADR. The `standards/`, `rules/`, `schemas/` and `scripts/` layout used by existing packs is not yet created. Node >=18, ESM, zero dependencies.
- Candidate rule-ID domains: `testevidence`, `teststrategy`, `testdesign`, `testexec`, `testnfr`, `testrelease`. Checked in test/skeleton.test.mjs against a hard-coded copy of the UIUXDesignStandards canonical-ID pattern (it would not detect later drift in UIUX; a live drift check is follow-up) (`domain.kebab-case-name`); all are admitted, so no grammar ADR is needed. None collides with EngineeringStandards `testing.*`.
- Vendored core (yaml, jsonschema, catalog, compliance) with provenance headers per UIUX ADR 0001: **not yet vendored**; to be done in a follow-up once the source version/hash is chosen.
- This pack owns the versioned core release-evidence schema (SWT-B04); not started.
