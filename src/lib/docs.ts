// Page-time helpers over the `vault` content collection (Astro runtime only).
import { getCollection, render, type CollectionEntry } from "astro:content";
import { getRoute, ROUTES } from "../data/routes";
import { buildEvidence, type EvidenceItem } from "./evidence";
import { containsFlag } from "./redact";

export type VaultEntry = CollectionEntry<"vault">;

let cache: Promise<Map<string, VaultEntry>> | undefined;
/** Entries keyed by vault-relative source path ("Exam Context/Exam Overview.md"). */
export function vaultBySource(): Promise<Map<string, VaultEntry>> {
  cache ??= getCollection("vault").then((all) => new Map(all.map((e) => [`${e.id}.md`, e])));
  return cache;
}

let evCache: Promise<EvidenceItem[]> | undefined;
export function evidenceItems(): Promise<EvidenceItem[]> {
  evCache ??= vaultBySource().then((m) => buildEvidence(new Map([...m].map(([k, e]) => [k, e.body ?? ""]))));
  return evCache;
}

export async function loadDoc(route: string) {
  const r = getRoute(route);
  if (!r?.source) throw new Error(`Route ${route} has no source document`);
  const entry = (await vaultBySource()).get(r.source);
  if (!entry) throw new Error(`Content collection has no entry for ${r.source}`);
  const { Content, headings } = await render(entry);
  return { route: r, entry, Content, headings, hasFlag: containsFlag(entry.body ?? "") };
}

/** Machines related to a document via its own frontmatter (never inferred from prose). */
export function relatedMachineIds(entry: VaultEntry): string[] {
  return ((entry.data as any).related_machines as string[] | undefined) ?? [];
}

/** Reverse relationship: documents of a group whose related_machines names the machine. */
export async function docsRelatedToMachine(machineId: string, navGroup: string) {
  const m = await vaultBySource();
  return ROUTES.filter((r) => r.navGroup === navGroup && r.source && ((m.get(r.source)?.data as any)?.related_machines ?? []).includes(machineId));
}
