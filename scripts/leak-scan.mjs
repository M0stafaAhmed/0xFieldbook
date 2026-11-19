// Post-build redaction gate for the COMPLETE published output, including the Pagefind index.
// Run after `astro build && pagefind`. Exits 1 on any hit. Prints counts and file names only:
// unredacted source flags are rejected, and public assets are scanned for known leak signatures.
// Pagefind stores fragments/index/meta gzip-compressed, so those files are decompressed before scanning;
// without that step this scan would be blind to the search index.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const siteRoot = process.cwd();
const dist = path.resolve(siteRoot, process.argv[2] ?? "dist");
const vaults = ["working-vault"].map((p) => path.resolve(siteRoot, p));
const FLAG = /ITGATE\{[^}\n]*\}/gi;

const walk = (dir) =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));

const values = new Set();
const vaultDocNames = new Set();
let maskedDocs = 0;
for (const v of vaults) {
  if (!fs.existsSync(v)) continue;
  for (const f of walk(v).filter((x) => x.endsWith(".md"))) {
    vaultDocNames.add(path.basename(f).toLowerCase());
    const src = fs.readFileSync(f, "utf-8");
    if (src.includes("IT{FLAG-SECRET}")) maskedDocs++;
    for (const m of src.matchAll(FLAG)) values.add(m[0]);
  }
}
if (values.size > 0) { console.error("leak-scan: unredacted exam-flag tokens remain in source Markdown"); process.exit(1); }
if (maskedDocs === 0) { console.error("leak-scan: no sanitized flag placeholders found in source Markdown"); process.exit(1); }
if (!fs.existsSync(dist)) { console.error(`leak-scan: ${dist} does not exist`); process.exit(1); }
if (!fs.existsSync(path.join(dist, "pagefind", "pagefind.js"))) { console.error("leak-scan: Pagefind index missing from dist; run pagefind before this scan"); process.exit(1); }

const needles = new Set();
for (const v of values) {
  needles.add(v.toLowerCase());
  const inner = v.slice(v.indexOf("{") + 1, -1);
  if (inner.length >= 8) needles.add(inner.toLowerCase());
  for (const tok of inner.match(/[A-Za-z0-9]{10,}/g) ?? []) if (/\d/.test(tok)) needles.add(tok.toLowerCase());
}
for (const pattern of ["itgate{", "itgate&#123;", "itgate%7b"]) needles.add(pattern);
const needleBufs = [...needles].map((n) => Buffer.from(n, "latin1"));

const files = walk(dist);
const hits = [];
let decompressed = 0;
const problems = [];
for (const f of files) {
  const rel = path.relative(dist, f);
  const raw = fs.readFileSync(f);
  const views = [raw];
  if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
    try { views.push(zlib.gunzipSync(raw)); decompressed++; } catch { problems.push(`undecodable gzip: ${rel}`); }
  }
  for (const b of views) {
    const lower = Buffer.from(b.toString("latin1").toLowerCase(), "latin1");
    if (needleBufs.some((n) => lower.includes(n))) { hits.push(rel); break; }
  }
  // the vaults themselves must never be part of the public output
  const segs = rel.split(path.sep).map((s) => s.toLowerCase());
  if (segs.includes("working-vault") || segs.includes("source-vault") || f.endsWith(".md") || vaultDocNames.has(path.basename(f).toLowerCase())) problems.push(`vault material in public output: ${rel}`);
}
if (hits.length || problems.length) {
  console.error(`leak-scan FAILED: ${hits.length} file(s) contain flag material${hits.length ? ": " + hits.join(", ") : ""}; ${problems.length} structural problem(s)${problems.length ? ": " + problems.join("; ") : ""}`);
  process.exit(1);
}
console.log(`leak-scan: scanned ${files.length} published files (${decompressed} gzip-compressed Pagefind files decompressed) with ${maskedDocs} sanitized source Markdown files and ${needles.size} leak signatures: 0 hits; no vault material in output`);
