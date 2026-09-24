import syncClientSchema from "../schemas/sync-client.schema.json";
import catalogDocument from "../catalog.json";
import collaborationSecurityExample from "../examples/collaboration-security.json";
import graphContextExample from "../examples/graph-context.json";
import mcpToolsExample from "../examples/mcp-tools.json";
import applyProposalInputSchema from "../schemas/apply-proposal-input.schema.json";
import approvalDecisionSchema from "../schemas/approval-decision.schema.json";
import auditEventSchema from "../schemas/audit-event.schema.json";
import catalogSchema from "../schemas/catalog.schema.json";
import changeProposalSchema from "../schemas/change-proposal.schema.json";
import changeSetSchema from "../schemas/change-set.schema.json";
import citationSchema from "../schemas/citation.schema.json";
import contractFixtureSchema from "../schemas/contract-fixture.schema.json";
import createProposalInputSchema from "../schemas/create-proposal-input.schema.json";
import discoverySchema from "../schemas/discovery.schema.json";
import exactRevisionSchema from "../schemas/exact-revision.schema.json";
import fileSelectorSchema from "../schemas/file-selector.schema.json";
import mcpWriteToolsSchema from "../schemas/mcp-write-tools.schema.json";
import mutationReceiptSchema from "../schemas/mutation-receipt.schema.json";
import paginationSchema from "../schemas/pagination.schema.json";
import proposalOperationSchema from "../schemas/proposal-operation.schema.json";
import providerProfileSchema from "../schemas/provider-profile.schema.json";
import revisionSelectorSchema from "../schemas/revision-selector.schema.json";
import secureHandoffSchema from "../schemas/secure-handoff.schema.json";
import sessionContextSchema from "../schemas/session-context.schema.json";
import sharedProtocolSchema from "../schemas/shared-protocol.schema.json";
import stableIdSchema from "../schemas/stable-id.schema.json";
import stableErrorSchema from "../schemas/stable-error.schema.json";
import toolDescriptorSchema from "../schemas/tool-descriptor.schema.json";

export const SCHEMA_IDS = Object.freeze({
  syncClient: "urn:vaultguard:workspace-contracts:1:sync-client",
  applyProposalInput: "urn:vaultguard:workspace-contracts:1:apply-proposal-input",
  approvalDecision: "urn:vaultguard:workspace-contracts:1:approval-decision",
  auditEvent: "urn:vaultguard:workspace-contracts:1:audit-event",
  catalog: "urn:vaultguard:workspace-contracts:1:catalog",
  changeProposal: "urn:vaultguard:workspace-contracts:1:change-proposal",
  changeSet: "urn:vaultguard:workspace-contracts:1:change-set",
  citation: "urn:vaultguard:workspace-contracts:1:citation",
  contractFixture: "urn:vaultguard:workspace-contracts:1:contract-fixture",
  createProposalInput: "urn:vaultguard:workspace-contracts:1:create-proposal-input",
  discovery: "urn:vaultguard:workspace-contracts:1:discovery",
  exactRevision: "urn:vaultguard:workspace-contracts:1:exact-revision",
  fileSelector: "urn:vaultguard:workspace-contracts:1:file-selector",
  mcpWriteTools: "urn:vaultguard:workspace-contracts:1:mcp-write-tools",
  mutationReceipt: "urn:vaultguard:workspace-contracts:1:mutation-receipt",
  pagination: "urn:vaultguard:workspace-contracts:1:pagination",
  proposalOperation: "urn:vaultguard:workspace-contracts:1:proposal-operation",
  providerProfile: "urn:vaultguard:workspace-contracts:1:provider-profile",
  revisionSelector: "urn:vaultguard:workspace-contracts:1:revision-selector",
  secureHandoff: "urn:vaultguard:workspace-contracts:1:secure-handoff",
  sessionContext: "urn:vaultguard:workspace-contracts:1:session-context",
  sharedProtocol: "urn:vaultguard:workspace-contracts:1:shared-protocol",
  stableId: "urn:vaultguard:workspace-contracts:1:stable-id",
  stableError: "urn:vaultguard:workspace-contracts:1:stable-error",
  toolDescriptor: "urn:vaultguard:workspace-contracts:1:tool-descriptor",
} as const);

export type SchemaId = (typeof SCHEMA_IDS)[keyof typeof SCHEMA_IDS];

function deepFreeze<T>(value: T, seen = new Set<object>()): Readonly<T> {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

const schemaRegistry = deepFreeze({
  syncClient: syncClientSchema,
  applyProposalInput: applyProposalInputSchema,
  approvalDecision: approvalDecisionSchema,
  auditEvent: auditEventSchema,
  catalog: catalogSchema,
  changeProposal: changeProposalSchema,
  changeSet: changeSetSchema,
  citation: citationSchema,
  contractFixture: contractFixtureSchema,
  createProposalInput: createProposalInputSchema,
  discovery: discoverySchema,
  exactRevision: exactRevisionSchema,
  fileSelector: fileSelectorSchema,
  mcpWriteTools: mcpWriteToolsSchema,
  mutationReceipt: mutationReceiptSchema,
  pagination: paginationSchema,
  proposalOperation: proposalOperationSchema,
  providerProfile: providerProfileSchema,
  revisionSelector: revisionSelectorSchema,
  secureHandoff: secureHandoffSchema,
  sessionContext: sessionContextSchema,
  sharedProtocol: sharedProtocolSchema,
  stableId: stableIdSchema,
  stableError: stableErrorSchema,
  toolDescriptor: toolDescriptorSchema,
});

export const schemas: Readonly<Record<string, unknown>> = schemaRegistry;

export const schemaDocuments: ReadonlyMap<string, unknown> = new Map(
  Object.values(schemaRegistry).map((schema) => [schema.$id, schema]),
);

export const catalog: Readonly<Record<string, unknown>> = deepFreeze(catalogDocument);

export const examples: Readonly<Record<string, unknown>> = deepFreeze({
  collaborationSecurity: collaborationSecurityExample,
  graphContext: graphContextExample,
  mcpTools: mcpToolsExample,
});
