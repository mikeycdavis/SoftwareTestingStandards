import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { check, evaluate, scanSecrets, MAX_DEPTH, MAX_NODES } from "../experimental/check-release-evidence.mjs";
const dir = new URL("../fixtures/release-evidence/", import.meta.url);
const VERDICTS = ["pass", "reject", "not-evaluated"];
// Fixture metadata (verdict, reason, case) is stripped before evaluation so it cannot trip or mask a check.
const strip = ({ verdict, reason, case: _case, ...record }) => record;
for (const f of readdirSync(dir).filter((x) => x.endsWith(".json"))) {
  test("fixture " + f, () => {
    const r = JSON.parse(readFileSync(new URL(f, dir)));
    assert.ok(VERDICTS.includes(r.verdict), "fixture must declare verdict: pass | reject | not-evaluated");
    assert.equal(r.case + ".json", f, "case must match the file name");
    const record = strip(r);
    const got = evaluate(record);
    const errs = check(record);
    assert.equal(got.verdict, r.verdict, "verdict for " + f + " got " + JSON.stringify(got));
    if (r.verdict === "pass") {
      assert.equal(r.reason, undefined, "a pass fixture has no reason");
      assert.deepEqual(got.errors, []);
      assert.deepEqual(got.notEvaluated, []);
      assert.deepEqual(errs, []);
      return;
    }
    // reason: one substring, or a list of substrings that must all be found
    const reasons = Array.isArray(r.reason) ? r.reason : [r.reason];
    assert.ok(reasons.length > 0 && reasons.every((x) => typeof x === "string" && x !== ""), "non-pass fixture needs a reason");
    assert.ok(errs.length > 0, "check() must never return an empty list unless the verdict is pass");
    if (r.verdict === "reject") {
      for (const reason of reasons) assert.ok(got.errors.some((e) => e.includes(reason)), "expected rejection for: " + reason + " got " + JSON.stringify(got));
    } else {
      assert.deepEqual(got.errors, [], "not-evaluated means no present-but-invalid value");
      for (const reason of reasons) {
        assert.ok(got.notEvaluated.some((e) => e.includes(reason)), "expected not-evaluated for: " + reason + " got " + JSON.stringify(got));
        assert.ok(errs.some((e) => e.startsWith("not-evaluated:") && e.includes(reason)));
      }
      // isolation: a not-evaluated fixture is absent only in what its reason names
      for (const e of got.notEvaluated) assert.ok(reasons.some((reason) => e.includes(reason)), "unexpected not-evaluated item: " + e);
    }
  });
}

test("non-object records are rejected", () => {
  for (const bad of [null, [], "x", 1, undefined, true]) {
    assert.deepEqual(check(bad), ["record must be an object"]);
    assert.deepEqual(evaluate(bad), { verdict: "reject", errors: ["record must be an object"], notEvaluated: [] });
  }
});

test("empty object is not-evaluated below production, never pass", () => {
  const got = evaluate({});
  assert.equal(got.verdict, "not-evaluated");
  assert.deepEqual(got.errors, []);
  assert.equal(got.notEvaluated.length, 5);
  assert.equal(check({}).length, 5);
});

test("empty production record rejects every absent required field", () => {
  const got = evaluate({ stage: "production" });
  assert.equal(got.verdict, "reject");
  assert.deepEqual(got.notEvaluated, []);
  for (const s of ["signing.status", "artifact.digest", "tests required", "source.dirty required", "production requires"]) assert.ok(got.errors.some((e) => e.includes(s)), s);
});

// ReDoS guard: every secret pattern must stay fast on large adversarial input. The bound is deliberately generous.
const SIZE = 200 * 1024;
const fill = (unit) => unit.repeat(Math.ceil(SIZE / unit.length)).slice(0, SIZE);
const ADVERSARIAL = [
  "eyJ", "eyJa", "eyJaaaaaaaaaaa.", "password", "\"password", "\"password\":", "\"a", "\"a\":", "a", " ", "-", "=",
  "AKIA", "ASIA", "ghp_", "github_pat_", "gho_", "Bearer ", "Bearer a", "Bearer 1", "--password ", "--password -", "-p",
  "mysql ", "mysql -", "a://", "a://a:", "a://a:a", "xoxb-", "npm_", "AIza", "sk-proj-", "sk_live_", "pass=", "pwd=",
  "AccountKey=", "SharedAccessSignature=", "?sig=", "&", "PRIVATE ", "client_", "aws_secret_",
];
const LIMIT_MS = 500;
for (const unit of ADVERSARIAL) {
  test("secret scan is linear on 200KB of " + JSON.stringify(unit), () => {
    const s = fill(unit);
    let t0 = performance.now();
    scanSecrets(s);
    const raw = performance.now() - t0;
    assert.ok(raw < LIMIT_MS, "raw scan took " + raw.toFixed(0) + "ms");
    t0 = performance.now();
    evaluate({ notes: s });
    const rec = performance.now() - t0;
    assert.ok(rec < LIMIT_MS, "record scan took " + rec.toFixed(0) + "ms");
  });
}

// Robustness: hostile shapes must be rejected, never thrown. These cannot be expressed as JSON fixtures (cycles, BigInt)
// or are impractically large as files (20,000 levels), so they are built here from the valid baseline fixture.
const baseline = () => strip(JSON.parse(readFileSync(new URL("valid-baseline.json", dir))));
const chain = (levels, wrap) => { let v = {}; for (let i = 0; i < levels; i++) v = wrap(v); return v; };
const rejectsWith = (record, substring) => {
  let got;
  assert.doesNotThrow(() => { got = evaluate(record); });
  assert.equal(got.verdict, "reject");
  assert.ok(got.errors.some((e) => e.includes(substring)), "expected " + substring + " got " + JSON.stringify(got.errors));
  assert.doesNotThrow(() => check(record));
};
test("20,000-level object nesting in a profile is rejected, not thrown", () => {
  rejectsWith({ ...baseline(), apple: chain(20000, (v) => ({ a: v })) }, "nesting deeper than " + MAX_DEPTH);
});
test("20,000-level array nesting inside a core group is rejected, not thrown", () => {
  const r = baseline(); r.tests[0].extra = chain(20000, (v) => [v]);
  rejectsWith(r, "nesting deeper than " + MAX_DEPTH);
});
test("nesting at exactly MAX_DEPTH passes; one level more is rejected", () => {
  // record = depth 1 and r.apple = depth 2; chain(k) is k + 1 nested objects, so its innermost one is at depth k + 2
  assert.equal(evaluate({ ...baseline(), apple: chain(MAX_DEPTH - 2, (v) => ({ a: v })) }).verdict, "pass");
  rejectsWith({ ...baseline(), apple: chain(MAX_DEPTH - 1, (v) => ({ a: v })) }, "nesting deeper");
});
test("circular objects are rejected, not thrown", () => {
  const a = baseline(); a.apple = {}; a.apple.self = a.apple;
  rejectsWith(a, "circular reference");
  const b = baseline(); b.loop = b;
  rejectsWith(b, "circular reference");
  const c = baseline(); c.tests[0].runs = [c.tests];
  rejectsWith(c, "circular reference");
});
test("a value shared by two parents without a cycle is not circular", () => {
  const shared = { scheme: "Release" };
  assert.equal(evaluate({ ...baseline(), apple: { a: shared, b: [shared, shared] } }).verdict, "pass");
});
test("exponential shared-reference graphs are bounded by MAX_NODES", () => {
  const r = { ...baseline(), apple: chain(40, (v) => ({ l: v, r: v })) };
  rejectsWith(r, "more than " + MAX_NODES + " values");
});
test("a record that cannot be serialised is rejected, not thrown", () => {
  rejectsWith({ ...baseline(), apple: { big: 1n } }, "cannot be serialised");
});
