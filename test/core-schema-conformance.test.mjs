// Conformance for release-evidence core 0.1.0 (initial freeze, not 1.0.0). It checks that:
//   1. the vendored schema file matches its recorded hash (drift test, decision S19b);
//   2. the schema agrees with the experimental evaluator on every fixture whose reason the schema can express;
//   3. the frozen enums match the evaluator's;
//   4. evaluate() keeps its frozen result shape.
// The validator below implements only the JSON Schema keywords the core schema uses. It is test support, not a product.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { evaluate, SIGNING, STAGES, KINDS, CORE } from "../experimental/check-release-evidence.mjs";

const schemaUrl = new URL("../schemas/release-evidence.core.0.1.0.schema.json", import.meta.url);
const hashUrl = new URL("../schemas/release-evidence.core.0.1.0.schema.json.sha256", import.meta.url);
const fixtureDir = new URL("../fixtures/release-evidence/", import.meta.url);
const lf = (s) => s.replace(/\r\n/g, "\n");
const schemaText = lf(readFileSync(schemaUrl, "utf8"));
const schema = JSON.parse(schemaText);

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const typeOk = (t, v) => (t === "object" ? isObj(v) : t === "array" ? Array.isArray(v) : t === "string" ? typeof v === "string" : t === "boolean" ? typeof v === "boolean" : false);
const KNOWN = new Set(["$schema", "$id", "title", "description", "x-coreVersion", "x-frozen", "x-evaluateShape", "$defs", "$ref", "type", "enum", "const", "required", "properties", "items", "minItems", "pattern", "allOf", "anyOf", "not", "if", "then"]);

export function valid(s, v, root = schema) {
  for (const k of Object.keys(s)) assert.ok(KNOWN.has(k), "validator does not support keyword " + k);
  if (s.$ref) {
    assert.ok(s.$ref.startsWith("#/$defs/"), "only local $defs refs are supported");
    if (!valid(root.$defs[s.$ref.slice("#/$defs/".length)], v, root)) return false;
  }
  if (s.type && !typeOk(s.type, v)) return false;
  if (s.enum && !s.enum.includes(v)) return false;
  if ("const" in s && v !== s.const) return false;
  if (s.pattern && !(typeof v === "string" && new RegExp(s.pattern).test(v))) return false;
  if (s.required && isObj(v) && !s.required.every((k) => Object.prototype.hasOwnProperty.call(v, k))) return false;
  if (s.properties && isObj(v)) {
    for (const [k, sub] of Object.entries(s.properties)) {
      if (Object.prototype.hasOwnProperty.call(v, k) && !valid(sub, v[k], root)) return false;
    }
  }
  if (Array.isArray(v)) {
    if (s.minItems !== undefined && v.length < s.minItems) return false;
    if (s.items) for (const x of v) if (!valid(s.items, x, root)) return false;
  }
  if (s.allOf && !s.allOf.every((x) => valid(x, v, root))) return false;
  if (s.anyOf && !s.anyOf.some((x) => valid(x, v, root))) return false;
  if (s.not && valid(s.not, v, root)) return false;
  if (s.if && valid(s.if, v, root) && s.then && !valid(s.then, v, root)) return false;
  return true;
}

test("schema file matches its recorded hash (vendored-copy drift)", () => {
  const recorded = lf(readFileSync(hashUrl, "utf8")).trim().split(/\s+/)[0];
  assert.match(recorded, /^[0-9a-f]{64}$/);
  assert.equal(createHash("sha256").update(schemaText).digest("hex"), recorded, "schema changed without updating its hash; a change to a frozen schema needs a new version");
});

test("schema declares core version 0.1.0 consistently with its id and file name", () => {
  assert.equal(schema["x-coreVersion"], "0.1.0");
  assert.ok(schema.$id.endsWith(":0.1.0"));
  assert.ok(decodeURIComponent(schemaUrl.pathname).endsWith("release-evidence.core.0.1.0.schema.json"));
});

test("frozen enums match the evaluator", () => {
  assert.deepEqual(schema.properties.signing.properties.status.enum, SIGNING);
  assert.deepEqual(schema.properties.stage.enum, STAGES);
  assert.deepEqual(schema.$defs.testEnvelope.properties.evidenceKind.enum, KINDS);
  assert.deepEqual(schema["x-evaluateShape"].verdict, ["pass", "reject", "not-evaluated"]);
});

test("residualRisks and testRuns are plural array-typed core names", () => {
  for (const n of ["residualRisks", "testRuns"]) {
    assert.equal(schema.properties[n].type, "array");
    assert.ok(CORE.includes(n));
  }
  assert.ok(!CORE.includes("residualRisk"), "singular residualRisk is not a core name");
});

// Reasons the schema does not express (evaluator-only rules). A fixture is schema-expressible when at least one of its
// reasons is not in this list.
const EVALUATOR_ONLY = ["secret material", "different digest", "redefines a core field", "no applicable run", "unknown test", "duplicate test id", "signing.status is not-evaluated", "signing.status is failed", "record nesting", "record contains", "record has more", "record cannot", "record must be"];
const reasonsOf = (r) => (Array.isArray(r.reason) ? r.reason : r.reason ? [r.reason] : []);
const strip = ({ verdict, reason, case: _c, ...record }) => record;

for (const f of readdirSync(fixtureDir).filter((x) => x.endsWith(".json"))) {
  const fx = JSON.parse(readFileSync(new URL(f, fixtureDir)));
  const record = strip(fx);
  if (fx.verdict === "pass" || fx.verdict === "not-evaluated") {
    test("schema accepts present values of fixture " + f, () => {
      assert.equal(valid(schema, record), true);
    });
  } else {
    const structural = reasonsOf(fx).some((r) => !EVALUATOR_ONLY.some((e) => r.includes(e)));
    if (structural) {
      test("schema rejects fixture " + f, () => {
        assert.equal(valid(schema, record), false);
      });
    }
  }
}

test("evaluate() result shape is frozen: exactly verdict, errors, notEvaluated", () => {
  for (const f of readdirSync(fixtureDir).filter((x) => x.endsWith(".json"))) {
    const got = evaluate(strip(JSON.parse(readFileSync(new URL(f, fixtureDir)))));
    assert.deepEqual(Object.keys(got).sort(), ["errors", "notEvaluated", "verdict"], f);
    assert.ok(["pass", "reject", "not-evaluated"].includes(got.verdict), f);
    assert.ok(Array.isArray(got.errors) && got.errors.every((x) => typeof x === "string"), f);
    assert.ok(Array.isArray(got.notEvaluated) && got.notEvaluated.every((x) => typeof x === "string"), f);
    if (got.verdict === "pass") assert.ok(got.errors.length === 0 && got.notEvaluated.length === 0, f);
    if (got.verdict === "reject") assert.ok(got.errors.length > 0, f);
    if (got.verdict === "not-evaluated") assert.ok(got.errors.length === 0 && got.notEvaluated.length > 0, f);
  }
  for (const bad of [null, [], "x", 1]) assert.deepEqual(evaluate(bad), { verdict: "reject", errors: ["record must be an object"], notEvaluated: [] });
});

test("absence is never a pass: an empty record is not-evaluated and not schema-invalid below production", () => {
  assert.equal(evaluate({}).verdict, "not-evaluated");
  assert.equal(valid(schema, {}), true);
  assert.equal(evaluate({ stage: "production" }).verdict, "reject");
  assert.equal(valid(schema, { stage: "production" }), false);
});

test("source.dirty is a boolean at every stage and false at production", () => {
  for (const stage of ["internal", "test", "staged"]) {
    assert.equal(valid(schema, { stage, source: { dirty: true } }), true);
    assert.equal(valid(schema, { stage, source: { dirty: "no" } }), false);
  }
  const prod = JSON.parse(readFileSync(new URL("valid-production-accepted.json", fixtureDir)));
  const rec = strip(prod);
  assert.equal(valid(schema, rec), true);
  assert.equal(valid(schema, { ...rec, source: { ...rec.source, dirty: true } }), false);
});

test("schema requires tests and testRuns at production and a non-blank string testId", () => {
  const rec = strip(JSON.parse(readFileSync(new URL("valid-production-accepted.json", fixtureDir))));
  assert.equal(valid(schema, rec), true);
  const { tests, ...noTests } = rec;
  const { testRuns, ...noRuns } = rec;
  assert.equal(valid(schema, noTests), false);
  assert.equal(valid(schema, noRuns), false);
  assert.equal(valid(schema, { ...rec, testRuns: [{ ...rec.testRuns[0], testId: "  " }] }), false);
  assert.equal(valid(schema, { ...rec, testRuns: [{ ...rec.testRuns[0], testId: 7 }] }), false);
  assert.equal(valid(schema, { ...rec, tests: [{ id: "" }] }), false);
  assert.equal(valid(schema, { ...noRuns, stage: "internal" }), true);
});

test("records are plain JSON data judged as one snapshot: accessors, proxies, toJSON and class instances are rejected uninvoked", () => {
  const prod = strip(JSON.parse(readFileSync(new URL("valid-production-accepted.json", fixtureDir))));
  assert.equal(evaluate(prod).verdict, "pass");
  const rejectsPlain = (rec) => { const got = evaluate(rec); assert.equal(got.verdict, "reject"); assert.ok(got.errors.some((e) => e.includes("plain JSON data")), JSON.stringify(got)); };
  // a getter that changes its answer on each read, and never gets to run
  let reads = 0;
  const changing = { ...prod, testRuns: [] };
  Object.defineProperty(changing, "tests", { enumerable: true, get() { reads++; return reads <= 3 ? [{ id: "t0" }] : []; } });
  rejectsPlain(changing);
  assert.equal(reads, 0, "the getter must not be invoked");
  // an accessor deeper in the record and inside an array
  const deep = { ...prod, notes: { a: [1] } };
  Object.defineProperty(deep.notes.a, 0, { enumerable: true, get() { reads++; return 1; } });
  rejectsPlain(deep);
  rejectsPlain({ ...prod, notes: Object.defineProperty({}, "setter", { enumerable: true, set(v) {} }) });
  // a toJSON method that would replace a branch before the secret scan
  let called = 0;
  const token = "ghp_" + "a".repeat(36);
  rejectsPlain({ ...prod, notes: { toJSON() { called++; return "x"; }, token } });
  assert.equal(called, 0, "toJSON must not be invoked");
  assert.equal(evaluate({ ...prod, notes: { token } }).verdict, "reject", "the secret is found when there is no toJSON");
  // proxies, class instances and dates
  rejectsPlain({ ...prod, notes: new Proxy({}, { get() { reads++; throw new Error("trap"); }, ownKeys() { reads++; throw new Error("trap"); } }) });
  rejectsPlain({ ...prod, notes: new (class X { constructor() { this.a = 1; } })() });
  rejectsPlain({ ...prod, notes: new Date(0) });
  rejectsPlain({ ...prod, testRuns: new Proxy(prod.testRuns, {}) });
  assert.equal(evaluate({ ...prod, notes: Object.assign(Object.create(null), { a: 1 }) }).verdict, "pass");
  // toJSON that is not enumerable, on an object or an array, as a function or an accessor, hiding data or a secret
  const hidden = (host, kind) => {
    let n = 0;
    const desc = kind === "fn" ? { value() { n++; return host === "arr" ? [] : "x"; } } : { get() { n++; return () => "x"; } };
    return { desc, count: () => n };
  };
  for (const kind of ["fn", "get"]) {
    const h1 = hidden("obj", kind); const o = { token }; Object.defineProperty(o, "toJSON", h1.desc);
    rejectsPlain({ ...prod, notes: o });
    const h2 = hidden("arr", kind); const a = [token]; Object.defineProperty(a, "toJSON", h2.desc);
    rejectsPlain({ ...prod, notes: a });
    const h3 = hidden("arr", kind); const t = [{ id: "t0" }]; Object.defineProperty(t, "toJSON", h3.desc);
    rejectsPlain({ ...prod, tests: t, testRuns: [] });
    const h4 = hidden("obj", kind); const top = { ...prod, tests: [] }; Object.defineProperty(top, "toJSON", h4.desc);
    rejectsPlain(top);
    assert.equal(h1.count() + h2.count() + h3.count() + h4.count(), 0, "no toJSON may be invoked");
  }
  // array subclasses and extra array properties
  rejectsPlain({ ...prod, notes: new (class A extends Array {})() });
  const extra = [1]; extra.note = "x";
  rejectsPlain({ ...prod, notes: extra });
  // values JSON would silently drop are rejected, not treated as absent
  for (const bad of [undefined, () => true, Symbol("s")]) {
    const got = evaluate({ ...prod, testRuns: [{ ...prod.testRuns[0], manual: bad }] });
    assert.equal(got.verdict, "reject");
    assert.ok(got.errors.some((e) => e.includes("not JSON")), JSON.stringify(got));
    assert.equal(evaluate({ ...prod, stage: "internal", signing: { status: "attested", notApplicable: bad } }).verdict, "reject");
  }
  // non-enumerable own properties would be dropped by JSON and turn invalid values into absent ones: reject them
  const hide = (o, k, v) => Object.defineProperty(o, k, { value: v, enumerable: false, writable: true, configurable: true });
  const ne1 = { ...prod, testRuns: [{ ...prod.testRuns[0] }] }; hide(ne1.testRuns[0], "manual", "yes");
  const ne2 = { ...prod, stage: "internal", signing: { status: "attested" } }; hide(ne2.signing, "notApplicable", "bogus");
  const ne3 = { ...prod }; hide(ne3, "residualRisks", "x");
  const ne4 = { ...prod, stage: "internal", signing: { } }; hide(ne4.signing, "status", "failed");
  const ne5 = { ...prod, stage: "internal" }; hide(ne5, "tests", "");
  // a non-enumerable array index is not plain data either (valid otherwise, so only the plain rule can reject it)
  const hideIdx = (arr, i) => Object.defineProperty(arr, i, { value: arr[i], enumerable: false, writable: true, configurable: true });
  const ne6 = { ...prod, tests: [...prod.tests] }; hideIdx(ne6.tests, 0);
  const ne7 = { ...prod, testRuns: [...prod.testRuns] }; hideIdx(ne7.testRuns, 0);
  const ne8 = { ...prod, residualRisks: [{ owner: "x" }] }; hideIdx(ne8.residualRisks, 0);
  for (const ne of [ne1, ne2, ne3, ne4, ne5, ne6, ne7, ne8]) rejectsPlain(ne);
  // boxed primitives (even with a swapped prototype) carry a value JSON cannot represent as data: reject, never drop
  rejectsPlain({ ...prod, notes: Object(5) });
  rejectsPlain({ ...prod, notes: Object.setPrototypeOf(Object(1n), null) });
  rejectsPlain({ ...prod, notes: Object.setPrototypeOf(new Number(5), Object.prototype) });
  // the snapshot keeps record key order, so errors are reported in record order
  const ordered = evaluate({ ...prod, x: { source: 1 }, y: { tests: 1 }, z: { stage: 1 } }).errors.filter((e) => e.startsWith("profile redefines"));
  assert.deepEqual(ordered, ["profile redefines a core field: x.source", "profile redefines a core field: y.tests", "profile redefines a core field: z.stage"]);
  // a revoked proxy as the whole record does not throw
  const rev = Proxy.revocable({}, {}); rev.revoke();
  rejectsPlain(rev.proxy);
  // a hole in an array is a null in the snapshot and is not evaluated as a run
  const sparse = { ...prod, testRuns: [, prod.testRuns[0]] };
  assert.equal(evaluate(sparse).verdict, "reject");
});
