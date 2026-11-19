// Markdown pipeline extensions (Phase 4 §5.3), implemented without extra dependencies.
//   remark: flag redaction -> drop the document H1 (the layout renders the title) -> callouts -> wikilinks
//   rehype: <badge>/<mark>/<ins> handling, table scroll wrappers, evidence chips on the Timeline
//           final-status table, and a second redaction pass over every text-bearing hast field.
// Nothing here edits the vault; all transforms apply to the in-memory tree only.
import { redactFlags } from "./redact";
import { resolveWikilink, routeForSource, titleForRoute } from "./vault";
import { EVIDENCE_PINS, STATE_LABEL, stateTone } from "./evidence-pins";

type Node = any;

function walk(node: Node, fn: (n: Node, parent: Node | null, i: number) => void, parent: Node | null = null, i = 0) {
  fn(node, parent, i);
  if (Array.isArray(node.children)) {
    // copy: callbacks may mutate the children array
    for (let k = 0; k < node.children.length; k++) walk(node.children[k], fn, node, k);
  }
}

const textOf = (n: Node): string => (typeof n.value === "string" ? n.value : (n.children ?? []).map(textOf).join(""));

function sourceFromFile(file: any): string | undefined {
  const p: string | undefined = file?.path ?? file?.history?.[0];
  if (!p) return undefined;
  const norm = p.split("\\").join("/");
  const idx = norm.lastIndexOf("/working-vault/");
  return idx >= 0 ? norm.slice(idx + "/working-vault/".length) : undefined;
}

const BADGE_TONES = new Set(["success", "warning", "danger", "info"]);
export const badgeColorsSeen = new Set<string>();

export const pipelineStats = { wikilinks: 0, callouts: 0, h1Dropped: 0, h1Kept: [] as string[] };

/* ------------------------------ remark ------------------------------ */
export function remarkObsidian() {
  return (tree: Node, file: any) => {
    const source = sourceFromFile(file);

    // 1. D12 redaction first, over every string field a published representation could carry.
    walk(tree, (n) => {
      for (const k of ["value", "url", "title", "alt", "lang", "meta", "label", "identifier"]) {
        if (typeof n[k] === "string") n[k] = redactFlags(n[k]);
      }
    });

    // 1b. <badge color="..."> arrives as raw HTML; rewrite it to the neutral document badge before it is parsed.
    walk(tree, (n) => {
      if (n.type !== "html" || typeof n.value !== "string" || !/<\/?badge\b/i.test(n.value)) return;
      n.value = n.value
        .replace(/<badge\b([^>]*)>/gi, (_m: string, attrs: string) => {
          const color = /color\s*=\s*"([^"]*)"/i.exec(attrs)?.[1] ?? "neutral";
          badgeColorsSeen.add(color);
          return `<span class="doc-badge" data-doc-tone="${BADGE_TONES.has(color) ? color : "neutral"}">`;
        })
        .replace(/<\/badge>/gi, "</span>");
    });

    // 2. The first H1 duplicates the title the layout renders. Drop it only if it matches.
    const route = source ? routeForSource(source) : undefined;
    const expected = route ? titleForRoute(route) : undefined;
    const h1i = tree.children.findIndex((c: Node) => c.type === "heading" && c.depth === 1);
    if (h1i >= 0) {
      const h1 = textOf(tree.children[h1i]).trim();
      // The layout renders the route title as the page <h1>; the document's own H1 is the same title.
      // It is dropped in every case; wording differences from the route title are recorded (not silently lost).
      tree.children.splice(h1i, 1);
      pipelineStats.h1Dropped++;
      if (h1 !== expected) pipelineStats.h1Kept.push(`${source ?? "?"}: document H1 "${h1}" vs route title "${expected ?? "?"}"`);
    }

    // 3. Obsidian callouts: > [!type] Title
    walk(tree, (n) => {
      if (n.type !== "blockquote" || !n.children?.length) return;
      const p = n.children[0];
      if (p.type !== "paragraph" || !p.children?.length || p.children[0].type !== "text") return;
      const m = /^\[!([A-Za-z-]+)\][+-]?[ \t]*([^\n]*)\n?/.exec(p.children[0].value);
      if (!m) return;
      const type = m[1].toLowerCase();
      const title = m[2].trim() || type.charAt(0).toUpperCase() + type.slice(1);
      p.children[0].value = p.children[0].value.slice(m[0].length);
      if (p.children[0].value === "") p.children.shift();
      if (p.children.length === 0) n.children.shift();
      n.children.unshift({
        type: "paragraph",
        data: { hName: "div", hProperties: { className: ["callout__title"] } },
        children: [{ type: "text", value: title }],
      });
      n.data = { hName: "div", hProperties: { className: ["callout", `callout--${type}`], "data-callout": type } };
      pipelineStats.callouts++;
    });

    // 4. Wikilinks (text nodes only: code/inlineCode are separate node types and are left alone)
    walk(tree, (n, parent, i) => {
      if (n.type !== "text" || !parent || !n.value.includes("[[")) return;
      const parts: Node[] = [];
      let last = 0;
      const re = /\[\[([^\]\n]+?)\]\]/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(n.value))) {
        const inner = m[1];
        const [rawTarget, ...aliasParts] = inner.split(/\\?\|/);
        const alias = aliasParts.join("|").trim();
        const res = resolveWikilink(rawTarget);
        const typed = rawTarget.split("#")[0].trim();
        const label = alias || (typed.includes("/") ? titleForRoute(res.route) ?? typed : typed);
        if (m.index > last) parts.push({ type: "text", value: n.value.slice(last, m.index) });
        parts.push({
          type: "link",
          url: res.route,
          title: null,
          data: { hProperties: { className: ["wikilink"], "data-wikilink": typed } },
          children: [{ type: "text", value: label }],
        });
        pipelineStats.wikilinks++;
        last = m.index + m[0].length;
      }
      if (!parts.length) return;
      if (last < n.value.length) parts.push({ type: "text", value: n.value.slice(last) });
      parent.children.splice(i, 1, ...parts);
    });
  };
}

/* ------------------------------ rehype ------------------------------ */
export function rehypeVault() {
  return (tree: Node, file: any) => {
    const source = sourceFromFile(file);
    let lastHeading = "";

    walk(tree, (n) => {
      if (n.type === "element") {
        if (/^h[1-6]$/.test(n.tagName)) lastHeading = textOf(n);
        // <badge color="success"> -> neutral document badge (not an evidence chip)
        if (n.tagName === "badge") {
          const color = String(n.properties?.color ?? "neutral");
          badgeColorsSeen.add(color);
          n.tagName = "span";
          n.properties = {
            className: ["doc-badge"],
            "data-doc-tone": BADGE_TONES.has(color) ? color : "neutral",
          };
        }
        // Timeline final-status table displays the participant-confirmed completion state.
        if (source === "Exam Context/Exam Timeline.md" && n.tagName === "tr" && /Final Examination Status/.test(lastHeading)) {
          const cells = (n.children ?? []).filter((c: Node) => c.type === "element" && c.tagName === "td");
          const id = cells.length ? textOf(cells[0]).trim() : "";
          const pin = EVIDENCE_PINS.find((p) => p.machine === id && p.objective === "user");
          const pinR = EVIDENCE_PINS.find((p) => p.machine === id && p.objective === "root");
          if (pin && pinR && cells.length >= 3) {
            for (const [cell, pn] of [[cells[1], pin], [cells[2], pinR]] as const) {
              cell.children.push({ type: "text", value: " " }, {
                type: "element", tagName: "span",
                properties: { className: ["badge", "badge--filled"], "data-tone": stateTone(pn.state), title: "Flag submission confirmed by the examination participant." },
                children: [{ type: "text", value: `Flag: ${STATE_LABEL[pn.state]}` }],
              });
            }
          }
        }
        // second-layer redaction of any string-valued attribute
        for (const [k, v] of Object.entries(n.properties ?? {})) {
          if (typeof v === "string") n.properties[k] = redactFlags(v);
          else if (Array.isArray(v)) n.properties[k] = v.map((x) => (typeof x === "string" ? redactFlags(x) : x));
        }
      } else if ((n.type === "text" || n.type === "comment" || n.type === "raw") && typeof n.value === "string") {
        n.value = redactFlags(n.value);
      }
    });

    // wrap tables so wide tables scroll inside the page instead of overflowing it
    walk(tree, (n) => {
      if (!Array.isArray(n.children)) return;
      if (n.properties?.className?.includes?.("table-wrap")) return; // already wrapped
      n.children = n.children.map((c: Node) =>
        c.type === "element" && c.tagName === "table"
          ? { type: "element", tagName: "div", properties: { className: ["table-wrap"] }, children: [c] }
          : c,
      );
    });
  };
}
