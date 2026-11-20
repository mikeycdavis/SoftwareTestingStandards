# ADR 0001: Skeleton, vendored core provenance, rule-ID domains (SWT-B01)

Status: **Proposed.** Nothing here is frozen; acceptance criteria need an owner decision.

- Layout mirrors the existing packs: `standards/`, `rules/`, `schemas/`, `scripts/`, `test/`, `templates/`, `docs/adr/`. Node >=18, ESM, zero dependencies.
- Candidate rule-ID domains: `testevidence`, `teststrategy`, `testdesign`, `testexec`, `testnfr`, `testrelease`. Verified by value against the UIUXDesignStandards canonical-ID pattern (`domain.kebab-case-name`); all are admitted, so no grammar ADR is needed. None collides with EngineeringStandards `testing.*`.
- Vendored core (yaml, jsonschema, catalog, compliance) with provenance headers per UIUX ADR 0001: **not yet vendored**; to be done in a follow-up once the source version/hash is chosen.
- This pack owns the versioned core release-evidence schema (SWT-B04); not started.
