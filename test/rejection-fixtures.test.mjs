import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { check } from "../experimental/check-release-evidence.mjs";
const dir = new URL("../fixtures/release-evidence/", import.meta.url);
for (const f of readdirSync(dir).filter((x) => x.endsWith(".json"))) {
  test("fixture " + f, () => {
    const r = JSON.parse(readFileSync(new URL(f, dir)));
    const errs = check(r);
    if (r.expect === "accept") assert.deepEqual(errs, []);
    else assert.ok(errs.some((e) => e.includes(r.reason)), "expected rejection for: " + r.reason + " got " + JSON.stringify(errs));
  });
}

test("non-object records are rejected", () => {
  for (const bad of [null, [], "x", 1]) assert.deepEqual(check(bad), ["record must be an object"]);
});
