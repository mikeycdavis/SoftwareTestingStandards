// EXPERIMENTAL: draft checker used only to exercise rejection fixtures. Not the schema; not frozen (C1).
// Scope: ONLY the checks below are enforced: artifact.digest, tests (non-empty; per-test evidenceKind, digest binding,
// command, exitCode), signing.status, stage (enum), source.dirty, a pattern-based secret scan, and protection of core
// groups from profile redefinition. approvals, residualRisk, rollback, provenance and distribution are NOT required or
// validated here. This checker has no "not-evaluated" outcome: every absent or invalid checked field is rejected, so it
// shows only that absence never passes, not how a real validator would report not-evaluated.
const has = (o, k) => o != null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
const CORE = ["source", "artifact", "tests", "signing", "stage", "approvals", "residualRisk", "rollback", "provenance", "distribution"];
const SIGNING = ["not-evaluated", "attested", "ingested", "failed"];
const STAGES = ["internal", "test", "staged", "production"];
const KINDS = ["automated", "manual"];
// One pattern per alternative so each can be covered by its own fixture. Case-sensitive except where noted.
const SECRET_PATTERNS = [/PRIVATE KEY/, /privateKey/, /password=/i, /"password"/i, /ghp_[A-Za-z0-9]{20,}/, /AKIA[0-9A-Z]{12,}/, /AWS_SECRET_ACCESS_KEY/, /client_secret/i];
const nonEmpty = (v) => typeof v === "string" && v !== "";
export function check(r) {
  const errs = [];
  if (r == null || typeof r !== "object" || Array.isArray(r)) return ["record must be an object"];
  if (!SIGNING.includes(r.signing?.status)) errs.push("signing.status required and in enum (absent or invalid is rejected, never a pass)");
  const artifactDigest = r.artifact?.digest;
  if (!nonEmpty(artifactDigest)) errs.push("artifact.digest required");
  if (!Array.isArray(r.tests) || r.tests.length === 0) errs.push("tests required and non-empty (no tests is not a pass)");
  for (const t of Array.isArray(r.tests) ? r.tests : []) {
    if (!KINDS.includes(t?.evidenceKind)) { errs.push("test evidenceKind required: automated or manual"); continue; }
    if (t.manual && t.evidenceKind === "automated") errs.push("manual evidence labelled automated");
    if (t.evidenceKind === "automated") {
      if (!nonEmpty(t.artifactDigest)) errs.push("test artifactDigest required (missing binding)");
      else if (t.artifactDigest !== artifactDigest) errs.push("test bound to a different digest");
      if (typeof t.command !== "string" || t.command.trim() === "") errs.push("automated evidence needs command (non-empty string)");
      if (t.exitCode !== 0) errs.push("automated evidence needs exitCode 0 (failing or missing exit code is not a pass)");
    }
  }
  if (!STAGES.includes(r.stage)) errs.push("stage required and in enum: internal, test, staged, production");
  if (typeof r.source?.dirty !== "boolean") errs.push("source.dirty required (boolean)");
  if (r.stage === "production" && r.source?.dirty !== false) errs.push("production requires source.dirty === false (dirty or missing is rejected)");
  const text = JSON.stringify(r);
  if (SECRET_PATTERNS.some((p) => p.test(text))) errs.push("secret material present");
  for (const [ns, v] of Object.entries(r)) {
    if (CORE.includes(ns) || !v || typeof v !== "object") continue;
    for (const o of Array.isArray(v) ? v : [v]) if (CORE.some((k) => has(o, k))) errs.push("profile redefines a core field");
  }
  return errs;
}
