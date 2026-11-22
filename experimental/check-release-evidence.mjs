// EXPERIMENTAL checker. The core structure it evaluates is frozen as release-evidence core 0.1.0 by
// schemas/release-evidence.core.0.1.0.schema.json (see docs/design/swt-core-0.1.0-freeze.md for exactly what is frozen
// and what stays open). The frozen parts are: the single envelope with per-kind branches (testRuns[] entries), tests[]
// as required test identities, source.dirty, the not-evaluated outcome (including the production-required set: artifact.digest,
// non-empty tests[], testRuns[] covering every test, source.dirty, signing.status and the stage and signing enums, and that a declared signing status
// not-evaluated never passes unless signing.notApplicable is declared, and a declared signing status failed rejects at every stage), the plural residualRisks[] and testRuns[]
// names, and the shape of evaluate()'s result. Everything
// else here, including the secret scan, is NOT frozen and may change.
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
//   - required fields: artifact.digest (non-empty string); tests (non-empty array of objects, each with a unique non-blank
//     id: the required test identities); testRuns (execution evidence: every test needs at least one run with its id, an
//     unmatched test is not-evaluated below production and rejected at production, and a run naming no test is rejected);
//     per run, testId, evidenceKind (automated | manual) and artifactDigest (non-empty string, equal to artifact.digest
//     when that is valid); for automated runs only, command (non-empty string) and exitCode (must be 0); signing.status
//     (a declared not-evaluated never passes: the verdict is not-evaluated unless signing.notApplicable declares a non-blank
//     basis and attestedBy; notApplicable is rejected when malformed or alongside any other status; a declared failed always rejects) (not-evaluated | attested |
//     ingested | failed); stage (internal | test | staged | production); source.dirty (boolean, required at every stage).
//   - stage "production" additionally requires source.dirty === false (a dirty source is valid below production).
//   - test.manual is optional; when present it must be a boolean (manual: "false", 1, null are rejected as an invalid
//     type), checked even when evidenceKind is absent or invalid. command and exitCode are judged only once evidenceKind
//     is known, because what is valid depends on the branch. A test with manual === true labelled evidenceKind
//     "automated" is rejected; a manual test carrying command or
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
//         secret_scanning), and token inside tokenize/tokenizer does not count. A real secret under such a key is missed;
//       - secret-key-name inspects string values (and secret-key-number 6+ digit numbers) only, not array or object
//         values; keys longer than 128 characters or containing an escape are missed. Other secret-word keys holding a
//         string are flagged even when they are metadata (tokensUsed, tokenUrl, secretVersion, secretsManagerArn,
//         passwordMinLength, passwordResetTested): known false positives;
//       - a CLI or mysql value may open with up to 4 quotes ('', "", '"...) and is still checked; a CLI value starting
//         with one dash is checked when 2+ value characters follow (--api-key -Hunter2), so --password -v and a following
//         --flag are not flagged, while a short option of 2+ letters after a secret flag is (a known false positive);
//         mysql -p-x is checked. BuildKit's safe form --secret id=... (docker build --secret id=npmrc,src=.npmrc) is not
//         flagged;
//       - mysql intervening arguments may be quoted (mysql -u "root" -phunter2 is flagged), up to 200 characters;
//       - not detected (known gaps): inline environment assignments with secret-named variables other than the listed
//         spellings (API_KEY=..., GITHUB_TOKEN=... npm test, export SECRET_KEY=...); short password options of tools other
//         than mysql (docker login -p, sshpass -p, sqlcmd -P, curl -u user:pw); Basic-auth headers (Authorization: Basic ...).
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
//     records. Records that are not plain JSON data (accessor properties, proxies, a toJSON of any enumerability, class instances,
//     array subclasses, undefined, function or symbol values) are rejected by the same walk without invoking anything; the record is then evaluated and secret-scanned as one JSON snapshot.
//   - core group names (CORE) may not appear as a key at ANY depth (objects and arrays) inside any non-core top-level
//     namespace (profile redefinition).
// A top-level residualRisks or testRuns that is present must be an array (0.1.0). The content of residualRisks is not
// validated; every testRuns entry is validated as an envelope (see above). Extra fields on a tests[] entry are ignored.
// NOT validated here: approvals, the content of residualRisks, rollback, provenance and distribution are neither required
// nor checked (they are in CORE only to block profile redefinition); source.revision, artifact.id, schemaVersion,
// timestamps, environment, result, retention and the remaining content of the manual branch (beyond its digest binding and the absence of command/exitCode); core
// group names nested inside core groups; unknown top-level keys whose values are not objects or arrays.
const has = (o, k) => o != null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const nonEmpty = (v) => typeof v === "string" && v.trim() !== "";
const ABSENT = Symbol("absent");
const INVALID = Symbol("invalid");
import { types } from "node:util";
export const CORE = ["source", "artifact", "tests", "testRuns", "signing", "stage", "approvals", "residualRisks", "rollback", "provenance", "distribution"];
export const SIGNING = ["not-evaluated", "attested", "ingested", "failed"];
export const STAGES = ["internal", "test", "staged", "production"];
export const KINDS = ["automated", "manual"];
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
// spelled out case-insensitively so that the case-sensitive mysql pattern matches <REDACTED> too
const anyCase = (w) => w.replace(/[a-z]/g, (c) => "[" + c + c.toUpperCase() + "]");
const MASK = R`(?:\*{3,64}|<` + anyCase("redacted") + R`>|\[` + anyCase("redacted") + R`\])`;
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
  ["pass-assign", rx(R`(?<![A-Za-z0-9])pass(?:wd)?=(?!(?:[0-9]{1,32}(?:\/[0-9]{1,32}|%)?|all)(?=[;&,\s]|\\[tnr]|"|$)|` + WHOLE + END_ASSIGN + R`)(?:'|\\"){0,4}[^;"\s&\\]`, "i")],
  // pwd=, except a path (/..., ~..., C:\..., . or ..), $(pwd), or a whole non-secret value
  ["pwd-assign", rx(R`(?<![A-Za-z0-9])pwd=(?![\/~]|[A-Za-z]:(?:\\\\|\/)|\.{1,2}(?=[\/;&\s]|\\|"|$)|\$\(pwd\)|` + WHOLE + END_ASSIGN + R`)(?:'|\\"){0,4}[^;"\s&\\]`, "i")],
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
  // a JSON key whose name contains a secret word, whose value is a string that is non-empty and not wholly a reference
  // or a mask (array and object values are not inspected).
  // pwd counts only inside a longer name (dbPwd, db_pwd; not pwd itself or OLDPWD, which pwd-key handles); token does
  // not count inside tokenize/tokenizer; metadata keys ending in ref, name, type, endpoint or scan(s/ned/ner/ners/ning)
// are not flagged.
  ["secret-key-name", rx(R`"(?=[^"\\]{0,128}?(?:password|passwd|passphrase|(?<=[^"\\])(?<!old)pwd|secret|token(?!iz)|apikey|api_key|privatekey|private_key))[^"\\]{1,128}(?<!ref|name|type|endpoint|scan(?:s|ned|ners?|ning)?)"\s{0,8}:\s{0,8}"(?!` + NS + R`")[^"]`, "i")],
  // a JSON key naming a password-like secret (not token counts or ttls), holding a 6+ digit number
  ["secret-key-number", /"(?=[^"\\]{0,128}?(?:password|passwd|passphrase|pwd|secret|apikey|api_key|privatekey|private_key))[^"\\]{1,128}"\s{0,8}:\s{0,8}-?\d{6}/i],
  // the JSON key "pwd" holding a non-empty string that is not a path or wholly a reference or a mask
  ["pwd-key", rx(R`"pwd"\s{0,8}:\s{0,8}"(?![\/~]|[A-Za-z]:(?:\\\\|\/)|` + NS + R`")[^"]`, "i")],
  // a CLI flag naming a secret, then = or spaces/tabs, then a value that is not a WHOLE non-secret value followed by END
  ["cli-secret-arg", rx(R`(?<![A-Za-z0-9_-])--?(?:password|passwd|pass|passphrase|token|secret(?!(?:=|(?:\s|\\t){1,8})id=)|api[-_]?key|client[-_]secret|access[-_]token|auth[-_]token)(?:=|(?:\s|\\t){1,8})(?!` + WHOLE + END + R`)(?:'|\\"){0,4}(?:-(?=[^\s"'\\-]{2}))?[^\s"'\\-]`, "i")],
  // mysql client -p<password> (first or later argument, optionally quoted); bare -p (prompt) and -P<port> do not match
  ["mysql-inline-password", rx(R`(?<![A-Za-z0-9_])mysql[a-z]{0,12}(?:\s(?:[^"\\]|\\.){0,200}?)?\s-p(?!` + WHOLE + END + R`)(?:'|\\"){0,4}-?[^\s"'\\-]`)],
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
// Limits for the snapshot walk below (which is iterative, so no recursion and no stack overflow). A value shared by two
// parents without a cycle is not circular. Every value counts toward MAX_NODES (the record itself, each object and array
// and each primitive), counting a value each time it is reached. The count is checked before a child is scheduled.
const NOT_JSON = "record contains a value that is not JSON (undefined, function or symbol)";
const NOT_PLAIN = "record must be plain JSON data (no accessors, proxies, custom toJSON or class instances)";
const TOO_MANY = "record has more than " + MAX_NODES + " values";
// Builds the one JSON snapshot that the whole evaluation and the secret scan use. Returns { error } or { value }. It reads
// only property descriptors, so no getter, setter, proxy trap, valueOf or toJSON can run, and it copies into plain
// null-prototype objects (and ordinary arrays), so no toJSON of the caller's can run later. A globally polluted Object.prototype or Array.prototype (a toJSON added to a built-in prototype) is out of scope: it is not something a record can do.
// A record must be plain JSON data: accessors, proxies, an own toJSON of any kind, non-plain prototypes (class instances, array subclasses, objects from another realm) and
// extra non-index array properties and non-enumerable own properties are rejected, symbol-keyed properties are ignored (as in JSON), and so are undefined, function and symbol values (JSON.stringify would
// silently drop them and turn an invalid present value into an absent one). A hole in an array becomes null, as in JSON.
function snapshotOf(r) {
  const root = { v: r, d: 1, set: (x) => { root.out = x; } };
  const stack = [root];
  const onPath = new Set();
  let nodes = 1;
  while (stack.length) {
    const f = stack.pop();
    if (f.exit) { onPath.delete(f.v); continue; }
    const v = f.v;
    if (typeof v === "bigint") return { error: "record cannot be serialised" };
    if (v === undefined || typeof v === "function" || typeof v === "symbol") return { error: NOT_JSON };
    if (v === null || typeof v !== "object") { f.set(v); continue; }
    if (types.isProxy(v)) return { error: NOT_PLAIN };
    if (onPath.has(v)) return { error: "record contains a circular reference" };
    if (f.d > MAX_DEPTH) return { error: "record nesting deeper than " + MAX_DEPTH + " levels" };
    onPath.add(v);
    stack.push({ v, exit: true });
    const proto = Object.getPrototypeOf(v);
    const names = Object.getOwnPropertyNames(v);
    if (names.includes("toJSON")) return { error: NOT_PLAIN };
    if (Array.isArray(v)) {
      if (proto !== Array.prototype) return { error: NOT_PLAIN };
      if (nodes + v.length > MAX_NODES) return { error: TOO_MANY };
      nodes += v.length;
      const out = new Array(v.length).fill(null);
      f.set(out);
      for (const k of names) {
        if (k === "length") continue;
        if (!/^(?:0|[1-9][0-9]*)$/.test(k) || Number(k) >= v.length) return { error: NOT_PLAIN };
      }
      for (let i = 0; i < v.length; i++) {
        const d = Object.getOwnPropertyDescriptor(v, i);
        if (!d) continue;
        if (d.get || d.set) return { error: NOT_PLAIN };
        if (!d.enumerable) return { error: NOT_PLAIN }; // JSON would not drop it, but it is not plain data and must not pass silently
        stack.push({ v: d.value, d: f.d + 1, set: (x) => { out[i] = x; } });
      }
    } else {
      if (proto !== Object.prototype && proto !== null) return { error: NOT_PLAIN };
      const out = Object.create(null);
      f.set(out);
      for (const k of names) {
        const d = Object.getOwnPropertyDescriptor(v, k);
        if (d.get || d.set) return { error: NOT_PLAIN };
        if (!d.enumerable) return { error: NOT_PLAIN }; // JSON would drop it, turning a present invalid value into an absent one
        if (++nodes > MAX_NODES) return { error: TOO_MANY };
        stack.push({ v: d.value, d: f.d + 1, set: (x) => { Object.defineProperty(out, k, { value: x, enumerable: true, writable: true, configurable: true }); } });
      }
    }
  }
  return { value: root.out };
}

function coreKeysIn(v, path, out) {
  if (Array.isArray(v)) v.forEach((x, i) => coreKeysIn(x, path + "[" + i + "]", out));
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) {
    if (CORE.includes(k)) out.push(path + "." + k);
    coreKeysIn(x, path + "." + k, out);
  }
  return out;
}

export function evaluate(input) {
  if (types.isProxy(input)) return { verdict: "reject", errors: [NOT_PLAIN], notEvaluated: [] };
  if (!isObj(input)) return { verdict: "reject", errors: ["record must be an object"], notEvaluated: [] };
  const snap = snapshotOf(input);
  if (snap.error) return { verdict: "reject", errors: [snap.error], notEvaluated: [] };
  // r is the one snapshot: every check below and the secret scan read these values, never the caller's object again.
  const r = snap.value;
  let text;
  try { text = JSON.stringify(r); } catch { return { verdict: "reject", errors: ["record cannot be serialised"], notEvaluated: [] }; }
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
    // signing.notApplicable: { basis, attestedBy }, both non-blank strings. Valid only with status "not-evaluated". A
    // declared status "not-evaluated" without it never passes: the verdict stays not-evaluated, at every stage.
    const na = field(signing, "notApplicable");
    if (na !== ABSENT) {
      if (!isObj(na)) errors.push("signing.notApplicable must be an object with basis and attestedBy");
      else {
        if (!nonEmpty(na.basis)) errors.push("signing.notApplicable.basis required (non-empty string)");
        if (!nonEmpty(na.attestedBy)) errors.push("signing.notApplicable.attestedBy required (non-empty string)");
      }
      if (status !== ABSENT && SIGNING.includes(status) && status !== "not-evaluated") errors.push("signing.notApplicable is only valid with status not-evaluated");
    }
    if (status === "failed") errors.push("signing.status is failed (a failed signing check is a rejection at every stage)");
    if (status === "not-evaluated" && na === ABSENT) notEvaluated.push("signing.status is not-evaluated and not declared not applicable (not a pass)");
  }

  const artifact = group(r, "artifact", errors);
  let artifactDigest;
  if (artifact !== INVALID) {
    const d = field(artifact, "digest");
    if (d === ABSENT) absent("artifact.digest required");
    else if (!nonEmpty(d)) errors.push("artifact.digest required (non-empty string)");
    else artifactDigest = d;
  }

  // tests[] = the REQUIRED test identities: a non-empty array of objects, each with a unique non-blank string id.
  // testRuns[] = EXECUTION EVIDENCE: each run is one envelope bound to a test by testId. Every valid required test must
  // have at least one run with its id; an unmatched requirement can never pass (not-evaluated below production, rejected
  // at production). The mapping is skipped for a testRuns that is present but not an array (the type error is reported).
  const testIds = new Set();
  let testsListed = false;
  if (!has(r, "tests")) absent("tests required and non-empty (no tests is not a pass)");
  else if (!Array.isArray(r.tests) || r.tests.length === 0) errors.push("tests required and non-empty (no tests is not a pass)");
  else {
    testsListed = true;
    Array.from(r.tests).forEach((t, i) => { // Array.from turns holes into undefined, so a sparse array rejects
      if (!isObj(t)) { errors.push("tests[" + i + "] must be an object"); return; }
      if (!has(t, "id")) absent("tests[" + i + "].id required (test identity)");
      else if (!nonEmpty(t.id)) errors.push("tests[" + i + "].id required (non-empty string)");
      else if (testIds.has(t.id)) errors.push("duplicate test id: " + t.id);
      else testIds.add(t.id);
    });
  }
  const runCount = new Map();
  if (has(r, "testRuns") && Array.isArray(r.testRuns)) Array.from(r.testRuns).forEach((t, i) => {
    if (!isObj(t)) { errors.push("testRuns[" + i + "] must be an object"); return; }
    if (!has(t, "testId")) absent("testRuns[" + i + "].testId required (binding to a test)");
    else if (!nonEmpty(t.testId)) errors.push("testRuns[" + i + "].testId required (non-empty string)");
    else if (testsListed) {
      if (!testIds.has(t.testId)) errors.push("run references unknown test: " + t.testId);
      else runCount.set(t.testId, (runCount.get(t.testId) || 0) + 1);
    }
    if (!has(t, "artifactDigest")) absent("test artifactDigest required (missing binding)");
    else if (!nonEmpty(t.artifactDigest)) errors.push("test artifactDigest required (missing binding: not a non-empty string)");
    else if (artifactDigest !== undefined && t.artifactDigest !== artifactDigest) errors.push("test bound to a different digest");
    // manual is optional; when present it must be a boolean, checked before any early return below. command and
    // exitCode depend on the branch, so they are judged only once evidenceKind is known.
    const manualInvalid = has(t, "manual") && typeof t.manual !== "boolean";
    if (manualInvalid) errors.push("test manual must be a boolean (invalid type)");
    if (!has(t, "evidenceKind")) { absent("test evidenceKind required: automated or manual"); return; }
    if (!KINDS.includes(t.evidenceKind)) { errors.push("test evidenceKind required: automated or manual (invalid value)"); return; }
    // only manual === true marks manual evidence
    if (t.manual === true && t.evidenceKind === "automated") errors.push("manual evidence labelled automated");
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
  if (testsListed && !(has(r, "testRuns") && !Array.isArray(r.testRuns))) {
    for (const id of testIds) if (!runCount.has(id)) absent("test " + id + " has no applicable run (an unmatched requirement cannot pass)");
  }

  if (stage === ABSENT) absent("stage required and in enum: internal, test, staged, production");
  else if (!STAGES.includes(stage)) errors.push("stage required and in enum: internal, test, staged, production");

  // residualRisks and testRuns are reserved plural core names (0.1.0): when present at the top level they must be arrays.
  // residualRisks content is not defined or validated in 0.1.0; testRuns entries are validated as envelopes above.
  for (const name of ["residualRisks", "testRuns"]) if (has(r, name) && !Array.isArray(r[name])) errors.push(name + " must be an array");

  const source = group(r, "source", errors);
  const dirty = source === INVALID ? INVALID : field(source, "dirty");
  if (dirty === ABSENT) absent("source.dirty required (boolean)");
  else if (dirty !== INVALID && typeof dirty !== "boolean") errors.push("source.dirty required (boolean)");
  if (production && dirty !== false) errors.push("production requires source.dirty === false (dirty or missing is rejected)");

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
