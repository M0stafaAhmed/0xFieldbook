// Timeline entries for the TimelineCertaintyToggle island (Phase 4 §3.4 / component inventory "Timeline").
// Entries are the "### N.M" sub-headings under each machine's "## N. MACHINE" section of Exam Timeline.md.
// Order = machine_sequence from frontmatter, then document order (the only order the record preserves).
// Certainty is a text classification over the existing wording; no timestamp is ever created:
//   exact       the section contains a preserved Kali-prompt timestamp (YYYY-MM-DD@HH:MM:SS)
//   approximate the section itself says timing is unavailable / inferred / established by sequence
//   undated     neither (order only)
import { redactFlags } from "./redact";

export type Certainty = "exact" | "approximate" | "undated";
export interface TimelineEntry { number: string; label: string; certainty: Certainty; timestamps: string[]; anchor: string }
export interface TimelineGroup { machine: string; heading: string; anchor: string; entries: TimelineEntry[] }

const STAMP = /\b\d{4}-\d{2}-\d{2}@\d{2}:\d{2}:\d{2}\b/g;
const APPROX = /exact time (?:is )?unavailable|time is unavailable|timing is (?:inferred|approximate)|order is established|established by the (?:examination record|sequence)|inferred from the sequence/i;

export function buildTimeline(body: string, sequence: string[], headings: { depth: number; slug: string; text: string }[]): TimelineGroup[] {
  const slugOf = (text: string) => {
    const h = headings.find((x) => x.text === text);
    if (!h) throw new Error(`timeline: no rendered heading "${text}"`);
    return h.slug;
  };
  const groups: TimelineGroup[] = [];
  let group: TimelineGroup | undefined;
  let entry: { number: string; label: string; heading: string; lines: string[] } | undefined;
  const flush = () => {
    if (!entry || !group) return;
    const text = entry.lines.join("\n");
    const stamps = [...new Set(text.match(STAMP) ?? [])];
    const certainty: Certainty = stamps.length ? "exact" : APPROX.test(text) ? "approximate" : "undated";
    group.entries.push({ number: entry.number, label: entry.label, certainty, timestamps: stamps.map(redactFlags), anchor: slugOf(entry.heading) });
    entry = undefined;
  };
  let inFence = false;
  for (const line of body.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
    if (!inFence) {
      let m: RegExpMatchArray | null;
      if ((m = /^## \d+\. (\S+-\d+) — (.+)$/.exec(line)) && sequence.includes(m[1])) {
        flush();
        group = { machine: m[1], heading: line.replace(/^## /, ""), anchor: slugOf(line.replace(/^## /, "")), entries: [] };
        groups.push(group);
        continue;
      }
      if (/^## /.test(line)) { flush(); group = undefined; continue; }
      if (group && (m = /^### (\d+\.\d+) (.+)$/.exec(line))) {
        flush();
        entry = { number: m[1], label: m[2].trim(), heading: line.replace(/^### /, ""), lines: [] };
        continue;
      }
    }
    entry?.lines.push(line);
  }
  flush();
  const order = groups.map((g) => g.machine);
  if (JSON.stringify(order) !== JSON.stringify(sequence)) throw new Error(`timeline: document order ${order} != machine_sequence ${sequence}`);
  return groups;
}
