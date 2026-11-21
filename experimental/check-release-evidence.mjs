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
//   - test.manual is optional; when present it must be a boolean (manual: "false", 1, null are rejected as an invalid
//     type). A test with manual === true labelled evidenceKind "automated" is rejected; a manual test carrying command or
//     exitCode (in any form) is rejected, because the manual branch carries neither.
//   - a pattern-based secret scan over the serialised record (SECRET_PATTERNS below; scanSecrets is exported). DEFENCE IN
//     DEPTH ONLY: the patterns are a known, incomplete list; a non-detection does not prove that no secret is present.
//     ReDoS: each pattern is a plain literal, starts with a fixed literal, or is anchored by a lookbehind, and every
//     repetition has an upper bound. The tests show the scan stays fast on large adversarial inputs; that is evidence on
//     the tested inputs, not a proof of linear time for every input.
//     Accepted limits, chosen to limit false positives (each is a known miss):
//       - a Bearer value needs 20+ token characters, or 8+ that include a digit (short all-letter tokens are missed);
//       - a numeric value is flagged only under keys naming a password/passwd/passphrase/pwd/secret/api-key/private-key
//         and only with 6+ digits; token-count or ttl style keys (max_tokens, tokenExpirySeconds) are not;
//       - pass= / passwd= test summaries are not flagged: 12, 12/12, 100% or all, ending at whitespace, ; & , or the end
//         of the value (pass=12 fail=0, pass=12,fail=0);
//       - pwd= values and "pwd" key values that are paths (/..., ~..., C:\...) are not flagged, nor pwd=. / pwd=.. /
//         pwd=$(pwd); the key-name rule counts pwd only inside a longer key (dbPwd, db_pwd), not "pwd" or "OLDPWD";
//       - secret-named JSON keys that are metadata are not flagged: a key ending in ref, name, type, endpoint, scan, scans,
//         scanned, scanner(s) or scanning (passwordSecretRef, secretName, tokenType, token_endpoint, secretScan,
//         secret_scanning), and token inside
//         tokenize/tokenizer does not count. A real secret under such a key is missed;
//       - url-credentials needs scheme://user:password@host where host is a hostname with optional :port followed by
//         /, ?, #, whitespace or the end; image refs such as docker://alpine:3.19@sha256:... are not flagged;
//       - pure REFERENCES and MASKS are accepted as non-secrets in CLI flag values, mysql -p values, secret-named JSON
//         string values, "pwd" values and pass=/pwd= assignments. A reference is $NAME, ${NAME}, %NAME% or ${{ a.b.c }}
//         (dotted identifiers only, at most one space of padding; ${{ 'literal' }}, operators and calls are flagged). A
//         mask is *** (3 to 64 stars), <redacted> or [redacted], any case. In a shell value it must be the WHOLE value:
//         bare, 'quoted' or "quoted" with matching quotes, followed by whitespace or the end of the value (; and & also end
//         a pass=/pwd= value). Anything attached ($X'abc', "$X"abc, $X\abc, ${X}abc) is flagged, and so is a reference
//         followed by ; | ) or other shell syntax in a CLI or mysql value (a known false positive);
//       - a literal secret shaped like $Name, ${Name} or %Name% is indistinguishable from a variable reference and is
//         accepted; the scan cannot know what a reference expands to;
//       - the literal-word patterns (password=, "password", client_secret, privateKey, AWS_SECRET_ACCESS_KEY) flag
//         whatever value follows, references and masks included.
//   - robustness: a record nested deeper than MAX_DEPTH levels, with more than MAX_NODES values (every object, array and
//     primitive counts, the record itself included, each time it is reached), containing a circular reference, or that
//     cannot be serialised (for example a BigInt) is rejected before any other check; evaluate() does not throw for such
//     records.
//   - core group names (CORE) may not appear as a key at ANY depth (objects and arrays) inside any non-core top-level
//     namespace (profile redefinition).
// NOT validated here: approvals, residualRisks, testRuns, rollback, provenance and distribution are neither required
// nor checked (they are in CORE only to block profile redefinition); source.revision, artifact.id, schemaVersion,
// timestamps, environment, result, retention and the remaining content of the manual branch (beyond its digest binding and the absence of command/exitCode); core
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
// One pattern per alternative so each is covered by its own fixture. Case-sensitive except where flagged "i".
// The scan runs over JSON.stringify(record), so a double quote inside a string value appears as \" and a tab as \t.
const R = String.raw;
const ID = R`[A-Za-z_][A-Za-z0-9_]{0,127}`;
// ${{ secrets.NAME }} / ${{ env.NAME }} / ${{ github.x.y }}: dotted identifiers only, at most one space of padding
// inside each brace pair; no quotes, operators or function calls.
const GHA = R`\$\{\{ ?[A-Za-z_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_-]{0,63}){0,8} ?\}\}`;
// a pure reference: ${{ ... }} | ${NAME} | $NAME | %NAME%
const REF = "(?:" + GHA + R`|\$\{` + ID + R`\}|\$` + ID + "|%" + ID + "%)";
// a masked value: *** (3 to 64 stars), <redacted>, [redacted] (any case)
const MASK = R`(?:\*{3,64}|<redacted>|\[redacted\])`;
// not a secret: a pure reference or a mask
const NS = "(?:" + REF + "|" + MASK + ")";
// a whole shell value that is not a secret: bare, 'single quoted' or "double quoted" (serialised as \"...\"); the
// closing quote must match the opening one
const WHOLE = "(?:" + NS + "|'" + NS + "'|" + R`\\"` + NS + R`\\"` + ")";
// end of a shell value: whitespace, a serialised tab/newline/return, the end of the serialised string, or the end
const END = R`(?=\s|\\[tnr]|"|$)`;
// end of an assignment value: as END, plus ; and & (connection strings, query strings)
const END_ASSIGN = R`(?=[;&\s]|\\[tnr]|"|$)`;
const rx = (src, flags) => new RegExp(src, flags);
export const SECRET_PATTERNS = [
  ["pem-private-key", /PRIVATE KEY/],
  ["privateKey-word", /privateKey/],
  ["password-assign", /password=/i],
  ["password-key", /"password"/i],
  // pass= / passwd=, except a test summary (12, 12/12, 100%, all; then an END_ASSIGN or ",") or a whole non-secret value
  ["pass-assign", rx(R`(?<![A-Za-z0-9])pass(?:wd)?=(?!(?:[0-9]{1,32}(?:\/[0-9]{1,32}|%)?|all)(?=[;&,\s]|\\[tnr]|"|$)|` + WHOLE + END_ASSIGN + R`)(?:'|\\")?[^;"\s&\\]`, "i")],
  // pwd=, except a path (/..., ~..., C:\..., . or ..), $(pwd), or a whole non-secret value
  ["pwd-assign", rx(R`(?<![A-Za-z0-9])pwd=(?![\/~]|[A-Za-z]:(?:\\\\|\/)|\.{1,2}(?=[\/;&\s]|\\|"|$)|\$\(pwd\)|` + WHOLE + END_ASSIGN + R`)(?:'|\\")?[^;"\s&\\]`, "i")],
  ["github-ghp", /(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{20,255}/],
  ["github-pat", /(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,255}/],
  ["github-gho", /(?<![A-Za-z0-9_])gho_[A-Za-z0-9]{20,255}/],
  ["github-ghs", /(?<![A-Za-z0-9_])ghs_[A-Za-z0-9]{20,255}/],
  ["github-ghu", /(?<![A-Za-z0-9_])ghu_[A-Za-z0-9]{20,255}/],
  ["github-ghr", /(?<![A-Za-z0-9_])ghr_[A-Za-z0-9]{20,255}/],
  ["aws-akia", /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])/],
  ["aws-asia", /(?<![A-Z0-9])ASIA[0-9A-Z]{16}(?![0-9A-Z])/],
  ["aws-secret-env", /aws_secret_access_key/i],
  ["client-secret", /client_secret/i],
  // a JSON key whose name contains a secret word, holding a non-empty string that is not wholly a reference or a mask.
  // pwd counts only inside a longer name (dbPwd, db_pwd; not pwd itself or OLDPWD, which pwd-key handles); token does
  // not count inside tokenize/tokenizer; metadata keys ending in ref, name, type, endpoint or scan(s/ned/ner/ners/ning)
// are not flagged.
  ["secret-key-name", rx(R`"(?=[^"\\]{0,128}?(?:password|passwd|passphrase|(?<=[^"\\])(?<!old)pwd|secret|token(?!iz)|apikey|api_key|privatekey|private_key))[^"\\]{1,128}(?<!ref|name|type|endpoint|scan(?:s|ned|ners?|ning)?)"\s{0,8}:\s{0,8}"(?!` + NS + R`")[^"]`, "i")],
  // a JSON key naming a password-like secret (not token counts or ttls), holding a 6+ digit number
  ["secret-key-number", /"(?=[^"\\]{0,128}?(?:password|passwd|passphrase|pwd|secret|apikey|api_key|privatekey|private_key))[^"\\]{1,128}"\s{0,8}:\s{0,8}-?\d{6}/i],
  // the JSON key "pwd" holding a non-empty string that is not a path or wholly a reference or a mask
  ["pwd-key", rx(R`"pwd"\s{0,8}:\s{0,8}"(?![\/~]|[A-Za-z]:(?:\\\\|\/)|` + NS + R`")[^"]`, "i")],
  // a CLI flag naming a secret, then = or spaces/tabs, then a value that is not a WHOLE non-secret value followed by END
  ["cli-secret-arg", rx(R`(?<![A-Za-z0-9_-])--?(?:password|passwd|pass|passphrase|token|secret|api[-_]?key|client[-_]secret|access[-_]token|auth[-_]token)(?:=|(?:\s|\\t){1,8})(?!` + WHOLE + END + R`)(?:'|\\")?[^\s"'\\-]`, "i")],
  // mysql client -p<password> (first or later argument, optionally quoted); bare -p (prompt) and -P<port> do not match
  ["mysql-inline-password", rx(R`(?<![A-Za-z0-9_])mysql[a-z]{0,12}(?:\s[^"]{0,200}?)?\s-p(?!` + WHOLE + END + R`)(?:'|\\")?[^\s"'\\-]`)],
  ["url-credentials", /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/[^\s\/:@"\\]{1,128}:[^\s\/@"\\]{1,128}@[A-Za-z0-9.-]{1,253}(?::\d{1,5})?(?=[\/?#\s'"\\]|$)/],
  ["slack-token", /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,255}/],
  ["npm-token", /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/],
  ["google-api-key", /(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/],
  ["stripe-live-key", /(?<![A-Za-z0-9_-])sk[-_]live[-_][A-Za-z0-9]{8,255}/],
  ["openai-project-key", /(?<![A-Za-z0-9_-])sk-proj-[A-Za-z0-9_-]{20,255}/],
  // 20+ token characters, or 8+ that include a digit
  ["bearer-token", /(?<![A-Za-z0-9])Bearer\s{1,8}(?:[A-Za-z0-9._~+\/=-]{20}|(?=[A-Za-z._~+\/=-]{0,64}[0-9])[A-Za-z0-9._~+\/=-]{8})/i],
  ["jwt", /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}/],
  ["azure-account-key", /AccountKey=[^;"\s\\]/i],
  ["azure-sas", /SharedAccessSignature=[^;"\s\\]/i],
  ["url-sig", /[?&]sig=[^&"\s\\]/i],
];
export const scanSecrets = (text) => SECRET_PATTERNS.filter(([, re]) => re.test(text)).map(([name]) => name);

function group(r, name, errors) {
  if (!has(r, name)) return ABSENT;
  if (!isObj(r[name])) { errors.push(name + " must be an object"); return INVALID; }
  return r[name];
}
const field = (g, key) => (g === ABSENT || !has(g, key) ? ABSENT : g[key]);

export const MAX_DEPTH = 256;
export const MAX_NODES = 1000000;
// Iterative walk (no recursion, so no stack overflow): returns an error string for a record that is too deep, too large
// or circular, else null. A value shared by two parents without a cycle is not circular. Every value counts toward
// MAX_NODES (the record itself, each object and array, and each primitive), counting a value each time it is reached.
// The count is checked before a child is scheduled, so the walk's own allocation is bounded by MAX_NODES.
const TOO_MANY = "record has more than " + MAX_NODES + " values";
function shapeError(r) {
  const stack = [{ v: r, d: 1 }];
  const onPath = new Set();
  let nodes = 1;
  const schedule = (x, d) => { if (x !== null && typeof x === "object") stack.push({ v: x, d }); };
  while (stack.length) {
    const f = stack.pop();
    if (f.exit) { onPath.delete(f.v); continue; }
    const v = f.v;
    if (onPath.has(v)) return "record contains a circular reference";
    if (f.d > MAX_DEPTH) return "record nesting deeper than " + MAX_DEPTH + " levels";
    onPath.add(v);
    stack.push({ v, exit: true });
    if (Array.isArray(v)) {
      if (nodes + v.length > MAX_NODES) return TOO_MANY;
      nodes += v.length;
      for (let i = 0; i < v.length; i++) schedule(v[i], f.d + 1);
    } else {
      for (const k in v) {
        if (!Object.prototype.hasOwnProperty.call(v, k)) continue;
        if (++nodes > MAX_NODES) return TOO_MANY;
        schedule(v[k], f.d + 1);
      }
    }
  }
  return null;
}

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
  const shape = shapeError(r);
  if (shape) return { verdict: "reject", errors: [shape], notEvaluated: [] };
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
    // manual is optional; when present it must be a boolean, and only manual === true marks manual evidence
    if (has(t, "manual") && typeof t.manual !== "boolean") errors.push("test manual must be a boolean (invalid type)");
    else if (t.manual === true && t.evidenceKind === "automated") errors.push("manual evidence labelled automated");
    if (t.evidenceKind === "automated") {
      if (!has(t, "command")) absent("automated evidence needs command (non-empty string)");
      else if (!nonEmpty(t.command)) errors.push("automated evidence needs command (non-empty string)");
      if (!has(t, "exitCode")) absent("automated evidence needs exitCode 0 (missing exit code is not a pass)");
      else if (t.exitCode !== 0) errors.push("automated evidence needs exitCode 0 (failing exit code is not a pass)");
    } else {
      // manual branch: carries neither command nor exitCode (one envelope, per-kind branches)
      if (has(t, "command")) errors.push("manual evidence must not carry command");
      if (has(t, "exitCode")) errors.push("manual evidence must not carry exitCode");
    }
  });

  if (stage === ABSENT) absent("stage required and in enum: internal, test, staged, production");
  else if (!STAGES.includes(stage)) errors.push("stage required and in enum: internal, test, staged, production");

  const source = group(r, "source", errors);
  const dirty = source === INVALID ? INVALID : field(source, "dirty");
  if (dirty === ABSENT) absent("source.dirty required (boolean)");
  else if (dirty !== INVALID && typeof dirty !== "boolean") errors.push("source.dirty required (boolean)");
  if (production && dirty !== false) errors.push("production requires source.dirty === false (dirty or missing is rejected)");

  let text;
  try { text = JSON.stringify(r); } catch { return { verdict: "reject", errors: ["record cannot be serialised"], notEvaluated: [] }; }
  for (const name of scanSecrets(text)) errors.push("secret material present: " + name);

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
