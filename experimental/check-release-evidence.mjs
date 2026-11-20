// EXPERIMENTAL: draft checker used only to exercise rejection fixtures. Not the schema; not frozen (C1).
export function check(r) {
  const errs = [];
  if (!r.signing || !r.signing.status) errs.push("signing.status required (absent is not-evaluated, never pass)");
  for (const t of r.tests ?? []) {
    if (t.evidenceKind === "automated" && t.artifactDigest !== r.artifact?.digest) errs.push("test bound to a different digest");
    if (t.manual && t.evidenceKind === "automated") errs.push("manual evidence labelled automated");
    if (t.evidenceKind === "automated" && !t.command) errs.push("automated evidence needs command");
  }
  if (r.source?.dirty === true && r.stage === "production") errs.push("dirty build cannot be production evidence");
  if (/PRIVATE KEY|privateKey|password/i.test(JSON.stringify(r))) errs.push("secret material present");
  for (const ns of ["apple", "android"]) if (r[ns] && (r[ns].source || r[ns].artifact || r[ns].tests || r[ns].signing || r[ns].stage)) errs.push("profile redefines a core field");
  return errs;
}
