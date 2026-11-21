// EXPERIMENTAL: draft checker used only to exercise rejection fixtures. Not the schema; not frozen (C1). Field names,
// stages and outcomes here are proposals (see docs/design/swt-b04-evidence-envelope-proposal.md) and may change.
//
// Outcomes: evaluate(record) returns { verdict: "pass" | "reject" | "not-evaluated", errors, notEvaluated }.
//   - A present-but-invalid value always rejects. A key that is present counts as present whatever its value (null included).
//   - At stage "production" an absent required field rejects. Below production (or when stage itself is absent, so
//     production cannot be established) an absent required field is listed in notEvaluated and the verdict is
//     "not-evaluated", never "pass".
//   - "pass" only when errors and notEvaluated are both empty. A non-object record is rejected.
//   check(record) returns evaluate().errors plus one "not-evaluated: ..." string per notEvaluated item, so absence never
//   yields an empty (passing) list.
//
// Validated here, and nothing else:
//   - required fields: artifact.digest (non-empty string); tests (non-empty array of objects); per test, evidenceKind
//     (automated | manual) and artifactDigest (non-empty string, equal to artifact.digest when that is valid); for
//     automated tests only, command (non-empty string) and exitCode (must be 0); signing.status (not-evaluated | attested |
//     ingested | failed); stage (internal | test | staged | production); source.dirty (boolean, required at every stage).
//   - stage "production" additionally requires source.dirty === false (a dirty source is valid below production).
//   - a test with manual: true labelled evidenceKind "automated" is rejected.
//   - a pattern-based secret scan over the serialised record (SECRET_PATTERNS below). DEFENCE IN DEPTH ONLY: the patterns
//     are a known, incomplete list; a non-detection does not prove that no secret is present.
//   - core group names (CORE) may not appear as a key at ANY depth (objects and arrays) inside any non-core top-level
//     namespace (profile redefinition).
// NOT validated here: approvals, residualRisks, testRuns, rollback, provenance and distribution are neither required
// nor checked (they are in CORE only to block profile redefinition); source.revision, artifact.id, schemaVersion,
// timestamps, environment, result, retention and the content of the manual branch beyond its digest binding; core
// group names nested inside core groups; unknown top-level keys whose values are not objects or arrays.
const has = (o, k) => o != null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const nonEmpty = (v) => typeof v === "string" && v.trim() !== "";
const ABSENT = Symbol("absent");
const INVALID = Symbol("invalid");
export const CORE = ["source", "artifact", "tests", "testRuns", "signing", "stage", "approvals", "residualRisks", "rollback", "provenance", "distribution"];
const SIGNING = ["not-evaluated", "attested", "ingested", "failed"];
const STAGES = ["internal", "test", "staged", "production"];
const KINDS = ["automated", "manual"];
// One pattern per alternative so each is covered by its own fixture. Case-sensitive except where flagged /i.
export const SECRET_PATTERNS = [
  ["pem-private-key", /PRIVATE KEY/],
  ["privateKey-word", /privateKey/],
  ["password-assign", /password=/i],
  ["password-key", /"password"/i],
  ["github-ghp", /ghp_[A-Za-z0-9]{20,}/],
  ["github-pat", /github_pat_[A-Za-z0-9_]{20,}/],
  ["github-gho", /gho_[A-Za-z0-9]{20,}/],
  ["github-ghs", /ghs_[A-Za-z0-9]{20,}/],
  ["github-ghu", /ghu_[A-Za-z0-9]{20,}/],
  ["github-ghr", /ghr_[A-Za-z0-9]{20,}/],
  ["aws-akia", /AKIA[0-9A-Z]{12,}/],
  ["aws-secret-env", /AWS_SECRET_ACCESS_KEY/],
  ["client-secret", /client_secret/i],
  // a JSON key whose name contains a secret word, holding a non-empty string value (e.g. "db_password":"x")
  ["secret-key-name", /"[^"]*(?:password|secret|token|apikey|api_key|privatekey|private_key)[^"]*"\s*:\s*"[^"]+"/i],
  ["cli-secret-arg", /(?:^|[\s"'])--?(?:password|passwd|token|secret|api[-_]?key)(?:=|\s+)[^\s"'-][^\s"']*/i],
  ["stripe-live-key", /sk[-_]live[-_][A-Za-z0-9]{8,}/],
  ["bearer-token", /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/i],
  ["jwt", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ["azure-account-key", /AccountKey=[^;"\s]+/i],
  ["azure-sas", /SharedAccessSignature=[^;"\s]+/i],
  ["url-sig", /[?&]sig=[^&"\s]+/i],
];

function group(r, name, errors) {
  if (!has(r, name)) return ABSENT;
  if (!isObj(r[name])) { errors.push(name + " must be an object"); return INVALID; }
  return r[name];
}
const field = (g, key) => (g === ABSENT || !has(g, key) ? ABSENT : g[key]);

function coreKeysIn(v, path, out) {
  if (Array.isArray(v)) v.forEach((x, i) => coreKeysIn(x, path + "[" + i + "]", out));
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) {
    if (CORE.includes(k)) out.push(path + "." + k);
    coreKeysIn(x, path + "." + k, out);
  }
  return out;
}

export function evaluate(r) {
  if (!isObj(r)) return { verdict: "reject", errors: ["record must be an object"], notEvaluated: [] };
  const errors = [];
  const notEvaluated = [];
  const stage = has(r, "stage") ? r.stage : ABSENT;
  const production = stage === "production";
  const absent = (msg) => (production ? errors.push(msg + " (absent at stage production)") : notEvaluated.push(msg + " (absent; not evaluated)"));

  const signing = group(r, "signing", errors);
  if (signing !== INVALID) {
    const status = field(signing, "status");
    if (status === ABSENT) absent("signing.status required");
    else if (!SIGNING.includes(status)) errors.push("signing.status required and in enum (invalid value is rejected)");
  }

  const artifact = group(r, "artifact", errors);
  let artifactDigest;
  if (artifact !== INVALID) {
    const d = field(artifact, "digest");
    if (d === ABSENT) absent("artifact.digest required");
    else if (!nonEmpty(d)) errors.push("artifact.digest required (non-empty string)");
    else artifactDigest = d;
  }

  if (!has(r, "tests")) absent("tests required and non-empty (no tests is not a pass)");
  else if (!Array.isArray(r.tests) || r.tests.length === 0) errors.push("tests required and non-empty (no tests is not a pass)");
  else r.tests.forEach((t, i) => {
    if (!isObj(t)) { errors.push("tests[" + i + "] must be an object"); return; }
    if (!has(t, "artifactDigest")) absent("test artifactDigest required (missing binding)");
    else if (!nonEmpty(t.artifactDigest)) errors.push("test artifactDigest required (missing binding: not a non-empty string)");
    else if (artifactDigest !== undefined && t.artifactDigest !== artifactDigest) errors.push("test bound to a different digest");
    if (!has(t, "evidenceKind")) { absent("test evidenceKind required: automated or manual"); return; }
    if (!KINDS.includes(t.evidenceKind)) { errors.push("test evidenceKind required: automated or manual (invalid value)"); return; }
    if (t.manual && t.evidenceKind === "automated") errors.push("manual evidence labelled automated");
    if (t.evidenceKind === "automated") {
      if (!has(t, "command")) absent("automated evidence needs command (non-empty string)");
      else if (!nonEmpty(t.command)) errors.push("automated evidence needs command (non-empty string)");
      if (!has(t, "exitCode")) absent("automated evidence needs exitCode 0 (missing exit code is not a pass)");
      else if (t.exitCode !== 0) errors.push("automated evidence needs exitCode 0 (failing exit code is not a pass)");
    }
  });

  if (stage === ABSENT) absent("stage required and in enum: internal, test, staged, production");
  else if (!STAGES.includes(stage)) errors.push("stage required and in enum: internal, test, staged, production");

  const source = group(r, "source", errors);
  const dirty = source === INVALID ? INVALID : field(source, "dirty");
  if (dirty === ABSENT) absent("source.dirty required (boolean)");
  else if (dirty !== INVALID && typeof dirty !== "boolean") errors.push("source.dirty required (boolean)");
  if (production && dirty !== false) errors.push("production requires source.dirty === false (dirty or missing is rejected)");

  const text = JSON.stringify(r);
  for (const [name, re] of SECRET_PATTERNS) if (re.test(text)) errors.push("secret material present: " + name);

  for (const ns of Object.keys(r)) {
    if (CORE.includes(ns)) continue;
    for (const hit of coreKeysIn(r[ns], ns, [])) errors.push("profile redefines a core field: " + hit);
  }

  const verdict = errors.length ? "reject" : notEvaluated.length ? "not-evaluated" : "pass";
  return { verdict, errors, notEvaluated };
}

export function check(r) {
  const { errors, notEvaluated } = evaluate(r);
  return [...errors, ...notEvaluated.map((m) => "not-evaluated: " + m)];
}
