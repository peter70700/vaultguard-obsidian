import { SCHEMA_IDS, type SchemaId } from "./registry.js";
import type { AuditEvent } from "./audit.js";
import type {
  ApprovalDecision,
  ApplyProposalInput,
  ChangeProposal,
  CreateProposalInput,
  FileSelector,
  MultiFileChangeSet,
  ProposalOperation,
} from "./proposals.js";
import type { RevisionSelector, StableError, ToolDescriptor } from "./types.js";
import {
  assertContract,
  canonicalStringify,
  parseContractJson,
  validateContract,
  type ValidationResult,
} from "./validator.js";

export interface ContractCodec<T> {
  readonly schemaId: SchemaId;
  readonly validate: (value: unknown) => ValidationResult;
  readonly is: (value: unknown) => value is T;
  readonly assert: (value: unknown) => asserts value is T;
  readonly parse: (text: string) => T;
  readonly serialize: (value: T) => string;
  readonly roundTrip: (value: T) => T;
}

export function createContractCodec<T>(schemaId: SchemaId): ContractCodec<T> {
  const validate = (value: unknown): ValidationResult => validateContract(schemaId, value);
  const is = (value: unknown): value is T => validate(value).valid;
  const assert = (value: unknown): asserts value is T => {
    assertContract(schemaId, value);
  };
  const parse = (text: string): T => parseContractJson(schemaId, text) as T;
  const serialize = (value: T): string => {
    assertContract(schemaId, value);
    return canonicalStringify(value);
  };
  const roundTrip = (value: T): T => parse(serialize(value));
  return Object.freeze({ schemaId, validate, is, assert, parse, serialize, roundTrip });
}

export const revisionSelectorCodec: ContractCodec<RevisionSelector> = createContractCodec<RevisionSelector>(SCHEMA_IDS.revisionSelector);
export const fileSelectorCodec = createContractCodec<FileSelector>(SCHEMA_IDS.fileSelector);
export const toolDescriptorCodec = createContractCodec<ToolDescriptor>(SCHEMA_IDS.toolDescriptor);
export const stableErrorCodec = createContractCodec<StableError>(SCHEMA_IDS.stableError);
export const auditEventCodec = createContractCodec<AuditEvent>(SCHEMA_IDS.auditEvent);
export const proposalOperationCodec = createContractCodec<ProposalOperation>(SCHEMA_IDS.proposalOperation);
export const createProposalInputCodec = createContractCodec<CreateProposalInput>(SCHEMA_IDS.createProposalInput);
export const changeProposalCodec = createContractCodec<ChangeProposal>(SCHEMA_IDS.changeProposal);
export const approvalDecisionCodec = createContractCodec<ApprovalDecision>(SCHEMA_IDS.approvalDecision);
export const applyProposalInputCodec = createContractCodec<ApplyProposalInput>(SCHEMA_IDS.applyProposalInput);
export const changeSetCodec = createContractCodec<MultiFileChangeSet>(SCHEMA_IDS.changeSet);
