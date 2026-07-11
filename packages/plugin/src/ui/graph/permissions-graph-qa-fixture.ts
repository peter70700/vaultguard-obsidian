import type { GraphElement } from "./permissions-graph-data";

export const PERMISSIONS_GRAPH_VIRTUAL_QA_PATH_PREFIX = "/synthetic/qa/";
export const PERMISSIONS_GRAPH_VIRTUAL_QA_SEED = 0x51a7_2026;

const FOLDER_COUNT = 64;
const FILE_COUNT = 2_000;
const USER_COUNT = 16;
const PERMISSIONS_PER_FILE = 5;

export interface PermissionsGraphVirtualQaFixtureCounts {
  readonly nodes: number;
  readonly edges: number;
  readonly folders: number;
  readonly files: number;
  readonly users: number;
  readonly containmentEdges: number;
  readonly permissionEdges: number;
  readonly expiringPermissionEdges: number;
}

export interface PermissionsGraphVirtualQaFixture {
  readonly seed: number;
  readonly elements: readonly GraphElement[];
  readonly folderIds: readonly string[];
  readonly fileIds: readonly string[];
  readonly userIds: readonly string[];
  readonly counts: PermissionsGraphVirtualQaFixtureCounts;
}

export interface PermissionsGraphVirtualQaFixtureValidation {
  readonly valid: boolean;
  readonly duplicateIds: readonly string[];
  readonly danglingEdgeIds: readonly string[];
  readonly invalidPathValues: readonly string[];
}

/** Fixed source-owned fixture. It never accepts a vault path or user input. */
export function createPermissionsGraphVirtualQaFixture(): PermissionsGraphVirtualQaFixture {
  const elements: GraphElement[] = [];
  const folderPaths = buildFolderPaths();
  const folderIds = folderPaths.map((path) => `folder:${path}`);
  const userIds = Array.from({ length: USER_COUNT }, (_, index) =>
    `user:synthetic-qa-user-${pad(index, 2)}`
  );
  const fileIds: string[] = [];
  let containmentEdges = 0;
  let expiringPermissionEdges = 0;

  for (let index = 0; index < folderPaths.length; index += 1) {
    const path = folderPaths[index];
    elements.push(freezeElement({
      data: {
        id: folderIds[index],
        kind: "folder",
        label: index === 0 ? "Synthetic QA Root/" : `Synthetic QA Folder ${pad(index, 2)}/`,
        path,
      },
      classes: "folder synthetic-qa",
    }));
    if (index === 0) continue;
    const parentIndex = index <= 7 ? 0 : 1 + ((index - 8) % 7);
    elements.push(freezeElement({
      data: {
        id: `contain:${folderIds[parentIndex]}->${folderIds[index]}`,
        kind: "containment",
        source: folderIds[parentIndex],
        target: folderIds[index],
      },
      classes: "containment synthetic-qa",
    }));
    containmentEdges += 1;
  }

  for (let index = 0; index < USER_COUNT; index += 1) {
    const syntheticUserId = `synthetic-qa-user-${pad(index, 2)}`;
    elements.push(freezeElement({
      data: {
        id: userIds[index],
        kind: "user",
        label: `Synthetic QA User ${pad(index, 2)}`,
        userId: syntheticUserId,
        role: index % 7 === 0 ? "admin" : index % 3 === 0 ? "editor" : "viewer",
        color: `hsl(${(index * 137) % 360} 62% 56%)`,
      },
      classes: "user synthetic-qa",
    }));
  }

  const leafFolderIndexes = Array.from({ length: FOLDER_COUNT - 8 }, (_, index) => index + 8);
  for (let index = 0; index < FILE_COUNT; index += 1) {
    const folderIndex = leafFolderIndexes[(index * 17 + 11) % leafFolderIndexes.length];
    const path = `${folderPaths[folderIndex]}/file-${pad(index, 4)}.md`;
    const fileId = `file:${path}`;
    fileIds.push(fileId);
    elements.push(freezeElement({
      data: {
        id: fileId,
        kind: "file",
        label: `Synthetic QA File ${pad(index, 4)}.md`,
        path,
      },
      classes: "file synthetic-qa",
    }));
    elements.push(freezeElement({
      data: {
        id: `contain:${folderIds[folderIndex]}->${fileId}`,
        kind: "containment",
        source: folderIds[folderIndex],
        target: fileId,
      },
      classes: "containment synthetic-qa",
    }));
    containmentEdges += 1;

    for (let permissionIndex = 0; permissionIndex < PERMISSIONS_PER_FILE; permissionIndex += 1) {
      const userIndex = (index * 7 + permissionIndex * 3) % USER_COUNT;
      const syntheticUserId = `synthetic-qa-user-${pad(userIndex, 2)}`;
      const level = (["read", "write", "admin"] as const)[
        (index + permissionIndex + PERMISSIONS_GRAPH_VIRTUAL_QA_SEED) % 3
      ];
      const expiring = (index * PERMISSIONS_PER_FILE + permissionIndex) % 17 === 0;
      if (expiring) expiringPermissionEdges += 1;
      elements.push(freezeElement({
        data: {
          id: `perm:${syntheticUserId}->${path}`,
          kind: "permission",
          source: userIds[userIndex],
          target: fileId,
          label: level,
          level,
          path,
          userId: syntheticUserId,
          expiring,
        },
        classes: `permission allow level-${level} synthetic-qa${expiring ? " expiring" : ""}`,
      }));
    }
  }

  const nodes = FOLDER_COUNT + FILE_COUNT + USER_COUNT;
  const permissionEdges = FILE_COUNT * PERMISSIONS_PER_FILE;
  const counts = Object.freeze({
    nodes,
    edges: containmentEdges + permissionEdges,
    folders: FOLDER_COUNT,
    files: FILE_COUNT,
    users: USER_COUNT,
    containmentEdges,
    permissionEdges,
    expiringPermissionEdges,
  });

  return Object.freeze({
    seed: PERMISSIONS_GRAPH_VIRTUAL_QA_SEED,
    elements: Object.freeze(elements),
    folderIds: Object.freeze(folderIds),
    fileIds: Object.freeze(fileIds),
    userIds: Object.freeze(userIds),
    counts,
  });
}

export function validatePermissionsGraphVirtualQaFixture(
  fixture: PermissionsGraphVirtualQaFixture,
): PermissionsGraphVirtualQaFixtureValidation {
  const seen = new Set<string>();
  const nodeIds = new Set<string>();
  const duplicateIds = new Set<string>();
  const edges: GraphElement[] = [];
  const invalidPathValues: string[] = [];

  for (const element of fixture.elements) {
    const id = element.data.id;
    if (seen.has(id)) duplicateIds.add(id);
    seen.add(id);
    if (element.data.source || element.data.target) edges.push(element);
    else nodeIds.add(id);
    if (
      typeof element.data.path === "string" &&
      !element.data.path.startsWith(PERMISSIONS_GRAPH_VIRTUAL_QA_PATH_PREFIX)
    ) {
      invalidPathValues.push(element.data.path);
    }
  }
  const danglingEdgeIds = edges
    .filter((edge) =>
      !nodeIds.has(edge.data.source ?? "") || !nodeIds.has(edge.data.target ?? "")
    )
    .map((edge) => edge.data.id)
    .sort(compareStrings);
  const duplicates = Array.from(duplicateIds).sort(compareStrings);
  const invalidPaths = Array.from(new Set(invalidPathValues)).sort(compareStrings);
  return Object.freeze({
    valid: duplicates.length === 0 && danglingEdgeIds.length === 0 && invalidPaths.length === 0,
    duplicateIds: Object.freeze(duplicates),
    danglingEdgeIds: Object.freeze(danglingEdgeIds),
    invalidPathValues: Object.freeze(invalidPaths),
  });
}

function buildFolderPaths(): string[] {
  const paths = ["/synthetic/qa/root"];
  for (let index = 1; index <= 7; index += 1) {
    paths.push(`/synthetic/qa/area-${pad(index, 2)}`);
  }
  for (let index = 8; index < FOLDER_COUNT; index += 1) {
    const parent = 1 + ((index - 8) % 7);
    paths.push(`/synthetic/qa/area-${pad(parent, 2)}/branch-${pad(index, 2)}`);
  }
  return paths;
}

function freezeElement(element: GraphElement): GraphElement {
  return Object.freeze({
    data: Object.freeze({ ...element.data }),
    classes: element.classes,
  });
}

function pad(value: number, width: number): string {
  return String(value).padStart(width, "0");
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
