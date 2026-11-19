import { defineConfig } from "astro/config";
import { unified } from "@astrojs/markdown-remark";
import { remarkObsidian, rehypeVault } from "./src/lib/obsidian-remark.ts";
import { flagLeakGate } from "./src/lib/leak-gate.ts";

// Static site generation only. No adapter, no server, no SSR, satisfying
// the locked requirement "Firebase Hosting must serve only the generated
// static output" (Phase 4 architecture report §5.8).
export default defineConfig({
  output: "static",
  outDir: "./dist",
  // No `site` URL is set yet: the Firebase Hosting URL is assigned in a
  // later phase (Phase 4 §5.8 / brief §2 "No Firebase deployment" in this
  // phase). Astro does not require `site` for a plain static build.
  build: {
    format: "directory",
  },
  // Phase 6: Markdown pipeline (flag redaction, callouts, wikilinks, badges). See src/lib/obsidian-remark.ts.
  // Astro 7 no longer bundles the remark/rehype processor, so it comes from @astrojs/markdown-remark
  // (the package Astro documents for keeping the Phase 4 remark -> rehype pipeline).
  // smartypants is OFF on purpose: it would rewrite quotes, dashes and ellipses in the examination prose.
  markdown: {
    processor: unified({
      remarkPlugins: [remarkObsidian],
      rehypePlugins: [rehypeVault],
      gfm: true,
      smartypants: false,
    }),
    shikiConfig: { theme: "github-dark" },
  },
  // Phase 6 / D12: fails the build if any original flag value or the flag-format token is published.
  integrations: [flagLeakGate()],
});
