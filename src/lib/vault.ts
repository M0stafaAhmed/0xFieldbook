// Node-only helpers shared by the Astro config (remark/rehype plugins, build gate)
// and the pages. Reads routes.json / pageMeta.json and lists working-vault/.
// Uses process.cwd() (the site root during `astro build`) rather than import.meta.url,
// because bundled modules do not keep their source location.
import fs from "node:fs";
import path from "node:path";

export interface RouteRow {
  source: string | null;
  route: string;
  pageType: string;
  navGroup: string;
  parentRoute: string | null;
  relatedRoutes: string[];
}

const SITE_ROOT = process.cwd();
export const VAULT_DIR = path.resolve(SITE_ROOT, "working-vault");

const readJson = <T>(rel: string): T => JSON.parse(fs.readFileSync(path.resolve(SITE_ROOT, rel), "utf-8"));

export const ROUTE_ROWS: RouteRow[] = readJson<RouteRow[]>("src/data/routes.json");
const PAGE_META = readJson<{ route: string; title: string }[]>("src/data/pageMeta.json");

export const titleForRoute = (route: string): string | undefined => PAGE_META.find((m) => m.route === route)?.title;

export function walkMarkdown(dir: string, base = dir): string[] {
  const out: string[] = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkMarkdown(p, base));
    else if (ent.name.endsWith(".md")) out.push(path.relative(base, p).split(path.sep).join("/"));
  }
  return out.sort();
}

const sourceToRoute = new Map<string, string>();
for (const r of ROUTE_ROWS) if (r.source) sourceToRoute.set(r.source, r.route);
export const routeForSource = (source: string): string | undefined => sourceToRoute.get(source);

// Vault-root path (no extension) -> source, and basename -> sources.
const vaultFiles = walkMarkdown(VAULT_DIR);
const byNoExt = new Map<string, string>(vaultFiles.map((f) => [f.slice(0, -3), f]));
const byBase = new Map<string, string[]>();
for (const f of vaultFiles) {
  const b = path.posix.basename(f, ".md").toLowerCase();
  byBase.set(b, [...(byBase.get(b) ?? []), f]);
}

export interface Resolved {
  source: string;
  route: string;
}

/** Phase 4 §4 model: exact vault-root path, then unique basename, else an error. Never a best guess. */
export function resolveWikilink(rawTarget: string): Resolved {
  let t = rawTarget.split("#")[0].trim();
  if (t.toLowerCase().endsWith(".md")) t = t.slice(0, -3);
  let source = byNoExt.get(t);
  if (!source && !t.includes("/")) {
    const c = byBase.get(t.toLowerCase()) ?? [];
    if (c.length > 1) throw new Error(`Ambiguous wikilink [[${rawTarget}]]: ${c.join(" | ")}`);
    source = c[0];
  }
  if (!source) throw new Error(`Unresolved wikilink [[${rawTarget}]]`);
  const route = sourceToRoute.get(source);
  if (!route) throw new Error(`Wikilink [[${rawTarget}]] resolves to ${source}, which has no route`);
  return { source, route };
}
