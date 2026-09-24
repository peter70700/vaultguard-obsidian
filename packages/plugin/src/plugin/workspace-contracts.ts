import {
  parseStableId,
  revisionSelectorCodec,
  type RevisionSelector,
} from "../../packages/workspace-contracts";

/** Plugin boundary for revision selectors received from persisted or remote JSON. */
export function decodePluginRevisionSelector(serialized: string): RevisionSelector {
  return revisionSelectorCodec.parse(serialized);
}

/** Validates a safe opaque ID and applies the workspace-revision brand at this boundary. */
export function createPluginExactRevisionSelector(workspaceRevisionId: string): RevisionSelector {
  const selector: RevisionSelector = Object.freeze({
    mode: "exact",
    workspaceRevisionId: parseStableId("workspaceRevision", workspaceRevisionId),
  });
  revisionSelectorCodec.assert(selector);
  return selector;
}

export function encodePluginRevisionSelector(selector: RevisionSelector): string {
  return revisionSelectorCodec.serialize(selector);
}
