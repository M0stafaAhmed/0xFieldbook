// Astro pre-Pagefind flag-safety gate for sanitized V2 source.
// Reject raw examination flag tokens in source Markdown and generated assets,
// while permitting the fixed publication placeholder IT{FLAG-SECRET}.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AstroIntegration } from "astro";
import { flagRegex } from "./redact";
import { VAULT_DIR, walkMarkdown } from "./vault";

function scanSource(): { rawCount: number; maskedFiles: number } {
  let rawCount = 0;
  let maskedFiles = 0;
  for (const dir of [VAULT_DIR]) {
    if (!fs.existsSync(dir)) continue;
    for (const f of walkMarkdown(dir)) {
      const content = fs.readFileSync(path.join(dir, f), "utf-8");
      rawCount += [...content.matchAll(flagRegex())].length;
      if (content.includes("IT{FLAG-SECRET}")) maskedFiles++;
    }
  }
  return { rawCount, maskedFiles };
}

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walkFiles(p));
    else out.push(p);
  }
  return out;
}

export function flagLeakGate(): AstroIntegration {
  return {
    name: "flag-leak-gate",
    hooks: {
      "astro:build:done": ({ dir, logger }) => {
        const { rawCount, maskedFiles } = scanSource();
        if (rawCount > 0) throw new Error("flag-leak-gate: unredacted exam-flag tokens remain in source Markdown");
        if (maskedFiles === 0) throw new Error("flag-leak-gate: no sanitized flag placeholders found in source Markdown");

        const outDir = fileURLToPath(dir);
        const patterns = ["itgate{", "itgate&#123;", "itgate%7b"];
        const hits: string[] = [];
        const files = walkFiles(outDir);
        for (const f of files) {
          const content = fs.readFileSync(f).toString("latin1").toLowerCase();
          if (patterns.some((p) => content.includes(p))) hits.push(path.relative(outDir, f));
        }
        if (hits.length) throw new Error(`flag-leak-gate FAILED: ${hits.length} published file(s) contain raw flag-format material: ${hits.join(", ")}`);
        logger.info(`flag-leak-gate: ${maskedFiles} sanitized source files, ${files.length} generated assets, 0 raw flag tokens`);
      },
    },
  };
}
