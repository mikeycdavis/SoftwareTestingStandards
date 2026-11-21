<!-- Charter revision 3; authoritative evidence: F:\GitHub Evidence\SoftwareTestingStandards\evidence-1\ -->
# Charter packet 01 — SoftwareTestingStandards

Status: DRAFT, read-only. Backlog IDs are draft labels, not issue numbers. See
`00-shared-conventions.md` (kept in `F:\GitHub Evidence\SoftwareTestingStandards\evidence-1\`, not in this repository).

## 1. Purpose (charter sentence)

Govern tester practice and test evidence: whether the tests for a change were designed, executed,
and recorded so that a green result means what a reader thinks it means.

> A passing test result means: for the test surfaces this project declared and the framework could
> actually evaluate, the recorded evidence supports it — and every risk, level, or environment not
> exercised remains visible.

## 2. Scope

- Test strategy and risk-based test planning; test levels (unit, integration, contract, system,
  end-to-end, acceptance) and what each may claim.
- Test design: requirement/acceptance-criteria traceability, oracles, boundary and negative cases,
  test data management, determinism.
- Test execution evidence: what was run, on what build, in what environment, with what result,
  retained where; no fabricated or stale results.
- Test-suite health: flakiness quarantine policy, retry policy, mutation/known-negative evidence,
  coverage as a signal with stated limits.
- Non-functional verification procedures: performance, load, soak, accessibility-test execution,
  security-test execution, resilience/chaos, upgrade/migration, compatibility matrices (the
  *how it is verified* — the *what must hold* stays with the owning pack).
- Exploratory testing charters and session records; defect reporting quality; regression selection;
  release test sign-off and known-issues disclosure.
- Test environments and test-data privacy (synthetic vs production data).

## 3. Non-goals

- Does **not** define product invariants (Engineering) or domain rules (Platform/Azure packs). It
  defines how those are verified.
- Does not own **test integrity prohibitions** already in EngineeringStandards (Standard 47:
  `testing.no-weakening-to-pass`, `testing.no-fabricated-results`, `testing.no-tautological-tests`)
  or **how the validator itself is tested** (Standard 29). It references them.
- Does not run or host tests, ship a test framework, or choose tools. Tool-neutral.
- Does not judge ML model evaluation (MachineLearningStandards) or browser/visual UI evidence rules
  (UIUXDesignStandards); it supplies the generic evidence envelope they can reuse.
- No live access to CI systems, test clouds, or device farms in v1; evidence is ingested or
  attested.
- Not a QA-staffing, certification, or process-maturity (TMMi) framework.

## 4. Authoritative first-party sources (all UNVERIFIED until opened — see conventions §3.7)

> Status note: this section is the pre-verification charter text. The source ledger in the evidence folder (hashed in `docs/evidence-index.md`) records which sources were later opened (tool-extracted, not human-reviewed) and governs; "unverified" below is superseded per source by the ledger.

| Source | Role |
| --- | --- |
| ISO/IEC/IEEE 29119 series (software testing: concepts, processes, documentation, techniques) | Primary vocabulary and process model; paywalled — extract only structure and cite by clause, never reproduce |
| ISO/IEC 25010 (product quality model) | Quality characteristics to classify non-functional test coverage |
| ISO/IEC/IEEE 12207 / 15289 (lifecycle, information items) | Where test information items sit in the lifecycle |
| ISTQB Glossary and Foundation/Advanced syllabi | De facto terminology; glossary only, not requirements |
| NIST SP 800-218 (SSDF) practice PW.7/PW.8 (code review, testing) and NIST SP 800-115 (technical security testing) | Security-test execution requirements |
| OWASP WSTG and ASVS | Security test case catalogs (referenced, not copied) |
| W3C WCAG-EM (evaluation methodology) | How accessibility conformance is *evaluated* (shared with UIUX) |
| Internal: EngineeringStandards 09, 29, 38, 47; MachineLearningStandards evaluation rules | Boundary partners |

Excluded as authorities: blog posts, tool vendor docs, "testing pyramid" folklore. They may appear
only as non-normative provenance.

## 5. Proposed hierarchy

Repository layout per conventions §2. Proposed standards (26 proposed rows; decision packet S23 estimates ~24, mirroring UIUX's 40 / Eng's 53
scale but smaller — the pack is process-heavy):

| # | Standard | Group |
| --- | --- | --- |
| 01 | Boundary with EngineeringStandards and platform packs | Foundations |
| 02 | Test evidence envelope (identity of build, env, command, result, retention); manual and automated evidence use separate schemas and one is never upgraded into the other | Foundations |
| 03 | Risk-based test strategy and test levels | Strategy |
| 04 | Traceability from requirement/acceptance criterion to test | Strategy |
| 05 | Test oracles and expected-result specification | Design |
| 06 | Boundary, negative, and error-path coverage | Design |
| 07 | Test data management and privacy: synthetic data, retention, production-data prohibition | Design |
| 08 | Test environments, fidelity, and explicitly documented differences from production | Execution |
| 09 | Determinism, flaky-test detection, quarantine with named owner and expiry date, retry policy | Execution |
| 10 | Test-strength evidence: red-first, mutation testing, negative controls; coverage as signal vs claim | Evidence |
| 11 | Regression selection and impact analysis | Execution |
| 12 | Exploratory testing charters and session records | Practice |
| 13 | Defect severity, reproduction evidence, triage, and closure rules | Practice |
| 14 | Performance, load, soak test procedure | NFR |
| 15 | Security test execution evidence | NFR |
| 16 | Accessibility test execution procedure | NFR |
| 17 | Resilience, failure-injection, recovery tests | NFR |
| 18 | Compatibility and configuration matrices (device/OS/browser/locale) | NFR |
| 19 | Upgrade, migration, rollback test procedure | NFR |
| 20 | Test results for AI/agent-run tests: attribution and honesty | AI |
| 21 | Release gates, exceptions, residual risk, known-issues disclosure, and human sign-off | Release |
| 22 | Test-suite maintenance and deletion governance | Maintenance |
| 22a | Tester independence: what independent review does and does not establish (revision addition; numbering to be settled at corpus freeze) | Practice |
| 22b | Test level definitions: unit, integration, contract, system, end-to-end, exploratory — what each may claim (revision addition; may merge with 03) | Strategy |
| 23 | Policy, applicability, exceptions (pack standard) | Framework |
| 24 | Evidence, assurance, compliance output (pack standard) | Framework |

Rule-ID domains (proposed, none collides with `testing.*`): `testevidence`, `teststrategy`,
`testdesign`, `testexec`, `testnfr`, `testrelease`.

Evidence surfaces: **static** (test-plan/policy files, test-file structure, CI config), **ingested**
(JUnit/TRX/xUnit/TAP-style results, coverage and mutation reports via a schema'd contract),
**attested** (exploratory records, sign-off). Most rules will be `assurance: partial` or `none`;
reading test files cannot show a test is meaningful.

Applicability: repository has tests/CI test steps or declares a test policy; `no-tests` declared is a
declaration, not a finding, and an untested repo that declares nothing is INDETERMINATE.

## 6. Initial threat model (failure modes the pack exists to prevent)

| ID | Failure | Detection posture |
| --- | --- | --- |
| T1 | Green run on a different build/commit than the one shipped | Evidence envelope binds result to build identity; mismatch = fail |
| T2 | Stale or copied results presented as current | Timestamp/commit freshness check; reuse flagged |
| T3 | Tests that cannot fail (tautologies, no assertions, mocks of the subject) | Heuristic detectors, `partial`; known-negative/mutation evidence required for automated claims |
| T4 | Flaky tests retried until green, hiding real failures | Retry/quarantine ledger; retry-to-pass without record = finding |
| T5 | Coverage gamed or misread as correctness | Coverage reported as signal; threshold-only claims rejected |
| T6 | Skipped/disabled tests silently reducing scope | Skip inventory diffed against prior release |
| T7 | Acceptance criteria with no test, or tests with no requirement | Traceability matrix gaps surfaced |
| T8 | Production data in test environments | Test-data policy attestation; pattern checks `partial` |
| T9 | AI/agent claims "tests pass" without running them | Require ingested result artifact tied to command and exit code |
| T10 | Non-functional claims (perf, a11y, security) with no executed procedure | NFR rules fail closed to `not-evaluated`, never pass |
| T11 | Environment drift making results non-reproducible | Environment declaration + parity attestation |

Meta-risk: the pack itself producing false confidence. Every automated rule needs unit, fixture and
known-negative/mutation tests (Eng Standard 29).

## 7. First backlog (draft labels; 14 items)

| Draft ID | Title | Notes |
| --- | --- | --- |
| SWT-B01 | Decide repo skeleton, vendored core provenance, rule-ID domains and grammar fit | Check catalog grammar admits prefixes |
| SWT-B02 | Boundary standard: ownership vs Eng 09/29/38/47, MLStandards, UIUX | Meta-test against shadowing |
| SWT-B03 | External source provenance: open, record and version ISO/IEC/IEEE 29119, 25010, NIST 800-218/115, OWASP | Resolves all UNVERIFIED |
| SWT-B04 | Define test evidence envelope schema (build identity, env, command, result, retention) and the versioned **core release-evidence schema** (artifact identity, source revision, build environment, tests, approvals, provenance, signing status, distribution stage, residual risks, rollback) | Foundation for all; owned here, pinned and extended by Apple/Android (no circular imports) |
| SWT-B05 | Ingestion contract for JUnit/TRX/coverage/mutation results | Mirror UIUX ADR 0002 |
| SWT-B06 | Applicability classifier for test surface | INDETERMINATE semantics |
| SWT-B07 | Policy schema + `project-policy.yml` template + init | Gate 0 |
| SWT-B08 | Core standards 02–07 (envelope, strategy, traceability, oracles, boundary, data) | First corpus slice |
| SWT-B09 | Rule catalog v1 freeze for slice 1 with assurance levels | Honest `partial/none` |
| SWT-B10 | Detectors: freshness, skip inventory, retry ledger, traceability gaps | Known-negative fixtures |
| SWT-B11 | Fixture repos: compliant, stale results, flaky-retried, untraceable, skipped | Minimal, single-purpose |
| SWT-B12 | Attestation model for exploratory sessions and release sign-off | Human surface |
| SWT-B13 | StandardsEnforcer adapter/applicability entry for this pack | Cross-repo item |
| SWT-B14 | Read-only adoption trial against real Standards repositories where applicable; record limits | Per Mike, on or before 2026-11-19 19:36 PST (2026-11-20T03:36Z): real Standards repos as read-only adopters; no changes to them |

## 8. Applied decisions and open questions

Applied (Mike, on or before 2026-11-19 19:36 PST (2026-11-20T03:36Z)): this pack owns the versioned core release-evidence schema shared by Apple
and Android; adoption is by read-only trials on real Standards repositories.

1. Should AI-run-test honesty live here or only in Eng 53? Recommendation: reference Eng 53, own the
   test-evidence angle.
2. Coverage thresholds: pack states no numbers; policy declares them.
3. Core release-evidence schema versioning and compatibility policy (semver, additive-only minor
   versions) to be settled in SWT-B04 before Apple/Android freeze their profiles.
