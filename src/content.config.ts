// Content collection over the approved working vault (Phase 4 §5.2). The vault is read in place
// from ./working-vault in the sanitized source repository. `type` must be one of the approved document types;
// properties outside the Phase 4 field list are not rejected (the list does not cover every property
// the vault carries) but are surfaced by the content manifest and the Phase 6 report.
import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { z } from "astro/zod";
import model from "./data/contentModel.json";

const TYPES = Object.keys(model.document_types) as [string, ...string[]];

const vault = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./working-vault", generateId: ({ entry }) => entry.replace(/\.md$/, "") }),
  schema: z.looseObject({
    type: z.enum(TYPES),
    project: z.string(),
    status: z.string().optional(),
    related_machines: z.array(z.string()).optional(),
    tags: z.array(z.string()).optional(),
  }),
});

export const collections = { vault };
