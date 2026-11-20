// EXPERIMENTAL: draft checker used only to exercise rejection fixtures. Not the schema; not frozen (C1).
const has = (o, k) => o != null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
const CORE = ["source", "artifact", "tests", "signing", "stage"];
export function check(r) {
  const errs = [];
  if (!r.signing || !r.signing.status) errs.push("signing.status required (absent is not-evaluated, never pass)");
  const artifactDigest = r.artifact?.digest;
  if (typeof artifactDigest !== "string" || artifactDigest === "") errs.push("artifact.digest required");
  for (const t of r.tests ?? []) {
    if (t.evidenceKind === "automated") {
      if (typeof t.artifactDigest !== "string" || t.artifactDigest === "") errs.push("test artifactDigest required (missing binding)");
      else if (t.artifactDigest !== artifactDigest) errs.push("test bound to a different digest");
    }
    if (t.manual && t.evidenceKind === "automated") errs.push("manual evidence labelled automated");
    if (t.evidenceKind === "automated" && !t.command) errs.push("automated evidence needs command");
  }
  if (r.source?.dirty === true && r.stage === "production") errs.push("dirty build cannot be production evidence");
  if (/PRIVATE KEY|privateKey|password/i.test(JSON.stringify(r))) errs.push("secret material present");
  for (const ns of ["apple", "android"]) if (has(r, ns) && CORE.some((k) => has(r[ns], k))) errs.push("profile redefines a core field");
  return errs;
}
