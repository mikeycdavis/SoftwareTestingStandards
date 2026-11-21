// EXPERIMENTAL: draft checker used only to exercise rejection fixtures. Not the schema; not frozen (C1).
// Scope: ONLY the fields checked below are enforced (artifact.digest, tests, per-test fields, signing.status, stage, source.dirty). The approvals, residualRisk, rollback, provenance and distribution groups are NOT required or validated here; they are only protected from profile redefinition. Absent-means-not-evaluated is demonstrated for the checked fields only.
const has = (o, k) => o != null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
const CORE = ["source", "artifact", "tests", "signing", "stage", "approvals", "residualRisk", "rollback", "provenance", "distribution"];
const SIGNING = ["not-evaluated", "attested", "ingested", "failed"];
const KINDS = ["automated", "manual"];
const nonEmpty = (v) => typeof v === "string" && v !== "";
export function check(r) {
  const errs = [];
  if (r == null || typeof r !== "object" || Array.isArray(r)) return ["record must be an object"];
  if (!SIGNING.includes(r.signing?.status)) errs.push("signing.status required and in enum (absent is not-evaluated, never pass)");
  const artifactDigest = r.artifact?.digest;
  if (!nonEmpty(artifactDigest)) errs.push("artifact.digest required");
  if (!Array.isArray(r.tests) || r.tests.length === 0) errs.push("tests required and non-empty (no tests is not a pass)");
  for (const t of Array.isArray(r.tests) ? r.tests : []) {
    if (!KINDS.includes(t?.evidenceKind)) { errs.push("test evidenceKind required: automated or manual"); continue; }
    if (t.manual && t.evidenceKind === "automated") errs.push("manual evidence labelled automated");
    if (t.evidenceKind === "automated") {
      if (!nonEmpty(t.artifactDigest)) errs.push("test artifactDigest required (missing binding)");
      else if (t.artifactDigest !== artifactDigest) errs.push("test bound to a different digest");
      if (!t.command) errs.push("automated evidence needs command");
      if (t.exitCode !== 0) errs.push("automated evidence needs exitCode 0 (failing or missing exit code is not a pass)");
    }
  }
  if (!nonEmpty(r.stage)) errs.push("stage required");
  if (typeof r.source?.dirty !== "boolean") errs.push("source.dirty required (boolean)");
  if (r.stage === "production" && r.source?.dirty !== false) errs.push("production requires source.dirty === false (dirty or missing is rejected)");
  if (r.source?.dirty === true) errs.push("dirty build is not release evidence");
  if (/PRIVATE KEY|privateKey|password=|"password"|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|AWS_SECRET_ACCESS_KEY|client_secret/i.test(JSON.stringify(r))) errs.push("secret material present");
  for (const [ns, v] of Object.entries(r)) {
    if (CORE.includes(ns) || !v || typeof v !== "object" || Array.isArray(v)) continue;
    if (CORE.some((k) => has(v, k))) errs.push("profile redefines a core field");
  }
  return errs;
}
