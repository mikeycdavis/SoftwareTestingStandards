import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Rule-ID grammar copied by value from UIUXDesignStandards schemas (domain.kebab-case-name).
// Candidate domains from the charter must all be admitted. Grammar is NOT frozen here (ADR 0001, Proposed).
const CANONICAL_ID = /^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$/;
const domains = ["testevidence", "teststrategy", "testdesign", "testexec", "testnfr", "testrelease"];

test("candidate rule-ID domains fit the portfolio grammar", () => {
  for (const d of domains) assert.match(`${d}.example-rule`, CANONICAL_ID);
});

test("no candidate domain shadows an EngineeringStandards domain", () => {
  for (const d of domains) assert.notEqual(d, "testing");
});

test("package declares zero dependencies and Node >=18", () => {
  const p = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
  assert.equal(p.dependencies, undefined);
  assert.equal(p.engines.node, ">=18");
});
