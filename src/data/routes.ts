// Typed accessor over routes.json, which is generated programmatically from
// reports/phase-4-route-map.csv (see tmp/4_routemap.py in the project workspace).
// This file is the single place that imports the raw JSON; every page and
// component should go through the helpers below rather than reading
// routes.json directly, so route logic (lookup, children, grouping) lives
// in one place.

import rawRoutes from "./routes.json";
import rawPageMeta from "./pageMeta.json";

export interface RouteEntry {
  /** working-vault relative path, or null for a generated index/search page. */
  source: string | null;
  route: string;
  pageType: string;
  navGroup: string;
  parentRoute: string | null;
  relatedRoutes: string[];
  /** Title derived from the document's own frontmatter/filename (never invented). */
  title: string;
  subtitle: string | null;
}

interface PageMetaEntry {
  route: string;
  title: string;
  subtitle: string | null;
  docType: string;
  machine: string | null;
}

const PAGE_META = rawPageMeta as PageMetaEntry[];

export const ROUTES: RouteEntry[] = (rawRoutes as Omit<RouteEntry, "title" | "subtitle">[]).map((r) => {
  const meta = PAGE_META.find((m) => m.route === r.route);
  return { ...r, title: meta?.title ?? r.route, subtitle: meta?.subtitle ?? null };
});

export function getRoute(route: string): RouteEntry | undefined {
  return ROUTES.find((r) => r.route === route);
}

export function getChildren(parentRoute: string): RouteEntry[] {
  return ROUTES.filter((r) => r.parentRoute === parentRoute);
}

export function getGroupRoutes(navGroup: string): RouteEntry[] {
  return ROUTES.filter((r) => r.navGroup === navGroup);
}

/** Builds a breadcrumb trail from the root to the given route, inclusive. */
export function getBreadcrumbs(route: string): RouteEntry[] {
  const trail: RouteEntry[] = [];
  let current = getRoute(route);
  const seen = new Set<string>();
  while (current && !seen.has(current.route)) {
    trail.unshift(current);
    seen.add(current.route);
    current = current.parentRoute ? getRoute(current.parentRoute) : undefined;
  }
  return trail;
}
