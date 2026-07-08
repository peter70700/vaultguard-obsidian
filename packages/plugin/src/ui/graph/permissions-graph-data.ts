/**
 * permissions-graph-data.ts — PURE cytoscape element builder.
 *
 * Maps already-fetched API records (vault members + per-path PathAccessSummary[]
 * [+ raw PermissionRule[]]) into cytoscape ElementDefinition-shaped objects
 * (nodes + edges). NO imports from obsidian or the network — fully unit-testable.
 *
 * VIEWER SCOPING (load-bearing, the whole security point): the file set comes
 * from `getBatchPathAccess`, whose backend returns EMPTY principals when the
 * caller cannot read a path. This builder OMITS any summary with zero principals
 * (the caller-can't-read sentinel) so no orphan / unreadable node or edge ever
 * renders. The graph can therefore never leak a file the viewer cannot read.
 *
 * Element shapes are a structural subset of cytoscape's ElementDefinition, so
 * the view passes them straight into `cytoscape({ elements })`.
 */

import { explainAccess, type ExplainLevel, type ExplainRule, type ExplainVaultRole } from "./permission-explain";

/** Access level vocabulary, same as the server's PermissionAccessLevel. */
export type GraphAccessLevel = "none" | "read" | "write" | "admin";

/** A vault member, structural subset of VaultMemberRecord (src/api/client.ts:154). */
export interface GraphMember {
  userId: string;
  role: ExplainVaultRole;
  displayName?: string;
  email?: string;
}

/** One principal on a path, subset of PathAccessPrincipal (src/api/client.ts:71). */
export interface GraphPrincipal {
  userId: string;
  level: GraphAccessLevel;
  role?: string;
  displayName?: string;
  email?: string;
}

/** A per-path access summary, subset of PathAccessSummary (src/api/client.ts:79). */
export interface GraphPathSummary {
  path: string;
  currentUserLevel?: GraphAccessLevel;
  principals: GraphPrincipal[];
}

export interface GraphBuilderInput {
  vaultId: string;
  members: GraphMember[];
  /** Viewer-scoped per-FILE summaries (zero-principal entries are omitted). */
  summaries: GraphPathSummary[];
  /**
   * Viewer-scoped per-FOLDER access summaries (access evaluated at each folder
   * path). Permission edges are drawn to the matching folder node exactly like
   * files, so folder-level grants are visible. Only folders that already exist
   * as nodes (ancestors of readable files) get edges; zero-principal entries add
   * nothing.
   */
  folderSummaries?: GraphPathSummary[];
  /**
   * Optional raw rules, used ONLY to flag expiring (dashed) permission edges.
   * When absent, edges are never flagged expiring.
   */
  rules?: ExplainRule[];
  /** Injectable "now" (ISO) for deterministic expiry detection. */
  now?: string;
  /** Optional pre-render node-type controls; defaults preserve existing output. */
  includeUsers?: boolean;
  includeFiles?: boolean;
  includeFolders?: boolean;
}

/**
 * Cytoscape-compatible element. `data.id` is always set (stable + deterministic);
 * edges additionally carry `source` + `target`. The graph is FLAT — folders and
 * the vault are ordinary dot nodes joined to their children by faint
 * `containment` edges (not cytoscape compound `parent` nesting), so the force
 * layout floats freely like Obsidian's native graph instead of penning children
 * inside parent boxes. Extra `data.*` attributes (level, role, expiring, …)
 * drive the view's selector stylesheet and click→explain lookups.
 */
export interface GraphElement {
  data: {
    id: string;
    source?: string;
    target?: string;
    label?: string;
    /** Node kind / edge kind, mirrored into `classes` for the stylesheet. */
    kind?: "user" | "file" | "folder" | "vault" | "permission" | "membership" | "containment";
    /** Permission edge: the resolved access level. */
    level?: GraphAccessLevel;
    /** Membership edge: the vault role. */
    role?: string;
    /** Permission edge: true when the grant is time-bound (future expiry). */
    expiring?: boolean;
    /** File/folder node: the vault-relative path it represents. */
    path?: string;
    /** Permission edge: the principal userId (for click→explain lookup). */
    userId?: string;
    [key: string]: unknown;
  };
  classes: string;
}

// ─── Stable id helpers ───────────────────────────────────────────────────────

const userId = (id: string): string => `user:${id}`;
const fileId = (path: string): string => `file:${path}`;
const folderId = (path: string): string => `folder:${path}`;
const permEdgeId = (uid: string, path: string): string => `perm:${uid}->${path}`;
const containmentEdgeId = (parent: string, child: string): string => `contain:${parent}->${child}`;

/**
 * Deterministic per-user colour so every user dot is visually distinct (and
 * stable across renders/sessions). Hashes the userId to an HSL hue with fixed
 * saturation/lightness that reads on both light and dark themes.
 */
export function colorForUser(uid: string): string {
  let hash = 0;
  for (let i = 0; i < uid.length; i++) {
    hash = (hash * 31 + uid.charCodeAt(i)) >>> 0;
  }
  const hue = hash % 360;
  return `hsl(${hue}, 62%, 55%)`;
}

/** Normalizes a path the way the backend does (collapse slashes, strip trailing). */
function normalizePath(path: string): string {
  const p = path.replace(/\/+/g, "/").replace(/\/$/, "");
  return p.startsWith("/") ? p : `/${p}`;
}

/** Ancestor folder paths of a file, from the vault root down to the immediate parent. */
export function ancestorFolders(filePath: string): string[] {
  const segments = filePath.split("/").filter(Boolean);
  // Drop the file segment; build cumulative folder paths.
  const folders: string[] = [];
  for (let i = 1; i < segments.length; i++) {
    folders.push("/" + segments.slice(0, i).join("/"));
  }
  return folders;
}

/** Whether a positive-level grant for (user, path) derives from a future-dated rule. */
function isExpiring(
  uid: string,
  role: ExplainVaultRole,
  path: string,
  rules: ExplainRule[] | undefined,
  now: string | undefined,
): boolean {
  if (!rules || rules.length === 0) return false;
  // Restrict to rules that could apply to THIS principal (their own user id,
  // the wildcard, or a role-based rule for their vault role) so another user's
  // rule never colors this edge.
  const lowerRole = role.toLowerCase();
  const candidate = rules.filter((rule) => {
    const ruleUser = (rule.userId ?? "").toLowerCase();
    const ruleRole = (rule.role ?? "").toLowerCase();
    return ruleUser === uid.toLowerCase() || rule.userId === "*" || (!!ruleRole && ruleRole === lowerRole);
  });
  if (candidate.length === 0) return false;
  const trace = explainAccess({ userId: uid, role, path, action: "read", rules: candidate, now });
  return trace.expiresAt !== null;
}

// ─── The builder ─────────────────────────────────────────────────────────────

/**
 * Builds the full element set for the connected vault, scoped to the viewer.
 *
 * Order of construction:
 *   1. the vault node,
 *   2. one user node per member + a membership edge user→vault,
 *   3. per readable summary: file + folder-chain nodes joined by faint
 *      containment edges (vault→folder→…→file), plus one permission edge per
 *      principal whose level !== none (allow/deny/expiring styling),
 *   4. a user node for any principal not already added (so edges have endpoints).
 *
 * Summaries with zero principals are skipped (viewer can't read → no leak).
 * All ids are stable + deduplicated.
 */
export function buildGraphElements(input: GraphBuilderInput): GraphElement[] {
  const elements: GraphElement[] = [];
  const seen = new Set<string>();
  const roleByUser = new Map<string, ExplainVaultRole>();
  const includeUsers = input.includeUsers !== false;
  const includeFiles = input.includeFiles !== false;
  const includeFolders = input.includeFolders !== false;

  const push = (el: GraphElement): void => {
    if (seen.has(el.data.id)) return;
    seen.add(el.data.id);
    elements.push(el);
  };

  const ensureUserNode = (uid: string, member?: GraphMember, principal?: GraphPrincipal): void => {
    if (!includeUsers) return;
    const label =
      member?.displayName?.trim() ||
      member?.email?.trim() ||
      principal?.displayName?.trim() ||
      principal?.email?.trim() ||
      uid;
    push({
      data: { id: userId(uid), kind: "user", label, userId: uid, color: colorForUser(uid) },
      classes: "user",
    });
  };

  // 1. User nodes from the member list. (No vault hub node and no membership
  //    edges — the graph centres on user→file permissions; each member's role
  //    still feeds the expiry calc and the click→explain narration.)
  for (const member of input.members) {
    roleByUser.set(member.userId, member.role);
    if (includeUsers) ensureUserNode(member.userId, member);
  }

  // Emit a faint containment edge parent→child. Deduplicated by id, so a folder
  // shared by many files links to its parent exactly once.
  const linkContainment = (parentNodeId: string, childNodeId: string): void => {
    push({
      data: {
        id: containmentEdgeId(parentNodeId, childNodeId),
        kind: "containment",
        source: parentNodeId,
        target: childNodeId,
      },
      classes: "containment",
    });
  };

  // Ensure a folder node exists and is chained to its ancestors by containment edges
  // (FLAT model — no compound `parent` nesting). Top-level folders/files are
  // roots (no vault parent), so each folder subtree floats freely and the graph
  // stays connected through the users that span files.
  const ensureFolderPath = (folderPath: string): string | null => {
    if (!includeFolders) return null;
    const folders = Array.from(new Set([...ancestorFolders(`${folderPath}/__folder`), normalizePath(folderPath)]));
    let parentId: string | null = null;
    for (const currentFolderPath of folders) {
      const id = folderId(currentFolderPath);
      const segments = currentFolderPath.split("/").filter(Boolean);
      // Trailing "/" makes a folder unmistakable from a same-named file.
      push({
        data: {
          id,
          kind: "folder",
          label: `${segments[segments.length - 1] ?? currentFolderPath}/`,
          path: currentFolderPath,
        },
        classes: "folder",
      });
      if (parentId) linkContainment(parentId, id);
      parentId = id;
    }
    return parentId;
  };

  const ensureFolderChain = (filePath: string): string | null => {
    if (!includeFolders) return null;
    const folders = ancestorFolders(filePath);
    let parentId: string | null = null;
    for (const folderPath of folders) {
      parentId = ensureFolderPath(folderPath);
    }
    return parentId; // immediate parent node for the file, or null at vault root
  };

  // 3. Files + permission edges, scoped to readable summaries.
  for (const rawSummary of input.summaries) {
    // VIEWER SCOPING: zero principals = caller can't read this path. Omit it
    // entirely — no file node, no folder node, no edge.
    if (!rawSummary.principals || rawSummary.principals.length === 0) {
      continue;
    }

    const path = normalizePath(rawSummary.path);
    const parentId = includeFolders ? ensureFolderChain(path) : null;
    if (includeFiles) {
      const segments = path.split("/").filter(Boolean);
      push({
        data: {
          id: fileId(path),
          kind: "file",
          label: segments[segments.length - 1] ?? path,
          path,
        },
        classes: "file",
      });
      if (parentId) linkContainment(parentId, fileId(path));

      addPermissionEdges(fileId(path), path, rawSummary.principals);
    }
  }

  // 4. Folder-level permission edges. Folders are evaluated at their own path
  //    (folder rules are stored with the folder path as the exact pattern), so
  //    a folder node gets user→folder edges exactly like a file. Only annotate
  //    folders that already exist as nodes (ancestors of readable files) to keep
  //    the set bounded and viewer-scoped.
  for (const folderSummary of input.folderSummaries ?? []) {
    if (!folderSummary.principals || folderSummary.principals.length === 0) continue;
    const path = normalizePath(folderSummary.path);
    const fid = folderId(path);
    if (!seen.has(fid) && !includeFiles && includeFolders) ensureFolderPath(path);
    if (!seen.has(fid)) continue;
    addPermissionEdges(fid, path, folderSummary.principals);
  }

  return elements;

  // ── helper (closure over push/roleByUser/input) ──────────────────────────
  function addPermissionEdges(targetId: string, targetPath: string, principals: GraphPrincipal[]): void {
    if (!includeUsers) return;
    for (const principal of principals) {
      // level "none" ⇒ no edge.
      if (!principal.level || principal.level === "none") continue;

      // The principal may not be in the member list (role-based grant resolved
      // to a user) — give them a node so the edge has an endpoint.
      const role = roleByUser.get(principal.userId);
      ensureUserNode(principal.userId, undefined, principal);

      const expiring = isExpiring(
        principal.userId,
        role ?? roleFromPrincipal(principal),
        targetPath,
        input.rules,
        input.now,
      );

      // Every drawn edge is an allow (the server collapses deny outcomes to
      // level "none", filtered above); the `allow` class is kept for forward-
      // compat with a future explicit-deny server. The `level-*` class carries
      // the RESOLVED access level (read/write/admin) so each user→target line is
      // coloured to match exactly what that user can do to that file or folder.
      const classes = `permission allow level-${principal.level}${expiring ? " expiring" : ""}`;

      push({
        data: {
          id: permEdgeId(principal.userId, targetPath),
          kind: "permission",
          source: userId(principal.userId),
          target: targetId,
          level: principal.level,
          label: principal.level,
          expiring,
          userId: principal.userId,
          path: targetPath,
        },
        classes,
      });
    }
  }
}

/** Best-effort vault role from a principal's role string (defaults to viewer). */
function roleFromPrincipal(principal: GraphPrincipal): ExplainVaultRole {
  const r = (principal.role ?? "").toLowerCase();
  if (r === "admin" || r === "editor" || r === "viewer") return r;
  return "viewer";
}

/** Re-exported so the view can narrate edges with the same level vocabulary. */
export type { ExplainLevel };
