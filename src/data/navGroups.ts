// Navigation group definitions for the persistent sidebar and mobile nav.
// Order here is the authoritative display order (Phase 4 architecture report, §3.1).
// Each group's destination routes are looked up from routes.json at render time,
// never hand-duplicated here, so the two data sources cannot drift apart.

export interface NavGroup {
  /** Must match the "navGroup" value used in routes.json exactly. */
  key: string;
  label: string;
  /** The group's own index/landing route. */
  indexRoute: string;
  /** Whether this group's sidebar entry expands to show child routes. */
  expandable: boolean;
}

export const NAV_GROUPS: NavGroup[] = [
  { key: "Dashboard", label: "Dashboard", indexRoute: "/", expandable: false },
  { key: "Examination Context", label: "Examination Context", indexRoute: "/exam", expandable: true },
  { key: "Examination Timeline", label: "Timeline", indexRoute: "/timeline", expandable: false },
  { key: "Machines", label: "Machines", indexRoute: "/machines", expandable: true },
  { key: "Methodology", label: "Methodology", indexRoute: "/methodology", expandable: true },
  { key: "Difficulties & Lessons", label: "Difficulties & Lessons", indexRoute: "/lessons", expandable: true },
  { key: "Reusable PoC Library", label: "Reusable PoCs", indexRoute: "/poc-library", expandable: true },
  { key: "Global Search", label: "Search", indexRoute: "/search", expandable: false },
];

export interface MachineMeta {
  id: string;
  slug: string;
  difficulty: string;
}

// The 5 examination machines, in difficulty order. This ordering matches
// Exam Timeline.md's `machine_sequence` frontmatter (Phase 4 content model),
// not an arbitrary alphabetical or invented order.
export const MACHINES: MachineMeta[] = [
  { id: "VE-01", slug: "ve-01", difficulty: "Very Easy" },
  { id: "EA-01", slug: "ea-01", difficulty: "Easy" },
  { id: "ME-01", slug: "me-01", difficulty: "Medium" },
  { id: "HA-01", slug: "ha-01", difficulty: "Hard" },
  { id: "IN-01", slug: "in-01", difficulty: "Insane" },
];
