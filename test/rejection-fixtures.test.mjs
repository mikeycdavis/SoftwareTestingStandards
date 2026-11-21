import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { check, evaluate } from "../experimental/check-release-evidence.mjs";
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
    assert.ok(typeof r.reason === "string" && r.reason !== "", "non-pass fixture needs a reason");
    assert.ok(errs.length > 0, "check() must never return an empty list unless the verdict is pass");
    if (r.verdict === "reject") {
      assert.ok(got.errors.some((e) => e.includes(r.reason)), "expected rejection for: " + r.reason + " got " + JSON.stringify(got));
    } else {
      assert.deepEqual(got.errors, [], "not-evaluated means no present-but-invalid value");
      assert.ok(got.notEvaluated.some((e) => e.includes(r.reason)), "expected not-evaluated for: " + r.reason + " got " + JSON.stringify(got));
      assert.ok(errs.some((e) => e.startsWith("not-evaluated:") && e.includes(r.reason)));
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
