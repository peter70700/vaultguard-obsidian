import { SCHEMA_IDS, schemaDocuments, type SchemaId } from "./registry.js";
import { isAnyStableId } from "./ids.js";

export type JsonPrimitive = boolean | null | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

type JsonRecord = Record<string, unknown>;
type Schema = boolean | JsonRecord;

export interface ValidationIssue {
  readonly path: string;
  readonly keyword: string;
  readonly message: string;
}

export interface ValidationResult {
  readonly valid: boolean;
  readonly issues: readonly ValidationIssue[];
}

const MAX_JSON_BYTES = 1_048_576;
const MAX_JSON_DEPTH = 64;
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const hasOwn = (value: object, key: PropertyKey): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

export class ContractValidationError extends Error {
  readonly issues: readonly ValidationIssue[];

  constructor(message: string, issues: readonly ValidationIssue[]) {
    super(message);
    this.name = "ContractValidationError";
    this.issues = issues;
  }
}

export function validateContract(schemaId: SchemaId | string, value: unknown): ValidationResult {
  // A registered document, or one definition inside it addressed by a JSON-pointer fragment
  // (`<document id>#/$defs/<name>`), such as one MCP write tool's closed input schema. A
  // fragment runs no document-level semantic check; only the schema it names applies.
  const fragment = typeof schemaId === "string" && schemaId.includes("#")
    ? resolveReference(schemaId, {})
    : undefined;
  const root = fragment ? fragment.root : schemaDocuments.get(schemaId);
  if (!isRecord(root) || (typeof schemaId === "string" && schemaId.includes("#") && !fragment)) {
    return {
      valid: false,
      issues: [{ path: "$", keyword: "$id", message: `Unknown schema ID: ${schemaId}` }],
    };
  }

  try {
    assertJsonValue(value);
  } catch (error) {
    const issues = error instanceof ContractValidationError && error.issues.length > 0
      ? error.issues
      : [{ path: "$", keyword: "jsonValue", message: error instanceof Error ? error.message : "Invalid JSON value." }];
    return Object.freeze({ valid: false, issues: Object.freeze([...issues]) });
  }
  const byteLength = utf8ByteLength(serializeCanonical(value, "$"));
  if (byteLength > MAX_JSON_BYTES) {
    return Object.freeze({
      valid: false,
      issues: Object.freeze([{
        path: "$",
        keyword: "maxBytes",
        message: `${byteLength} exceeds ${MAX_JSON_BYTES}.`,
      }]),
    });
  }

  const issues: ValidationIssue[] = [];
  validateSchema(fragment ? fragment.schema : root, value, "$", root, issues);
  if (issues.length === 0 && !fragment) runSemanticChecks(schemaId, value, issues);
  return Object.freeze({ valid: issues.length === 0, issues: Object.freeze(issues) });
}

export function assertContract(schemaId: SchemaId | string, value: unknown): asserts value is JsonValue {
  const result = validateContract(schemaId, value);
  if (!result.valid) {
    throw new ContractValidationError(
      `Value does not satisfy ${schemaId}: ${result.issues.map(formatIssue).join("; ")}`,
      result.issues,
    );
  }
}

export function parseContractJson<T extends JsonValue = JsonValue>(
  schemaId: SchemaId | string,
  text: string,
): T {
  if (typeof text !== "string") {
    throw new ContractValidationError("Contract JSON must be a string.", [
      { path: "$", keyword: "type", message: "Expected a JSON string." },
    ]);
  }
  const byteLength = utf8ByteLength(text);
  if (byteLength > MAX_JSON_BYTES) {
    throw new ContractValidationError("Contract JSON exceeds the 1 MiB input limit.", [
      { path: "$", keyword: "maxBytes", message: `${byteLength} exceeds ${MAX_JSON_BYTES}.` },
    ]);
  }

  try {
    new StrictJsonScanner(text).scan();
  } catch (error) {
    const message = error instanceof Error ? error.message : "Malformed JSON.";
    throw new ContractValidationError(`Malformed contract JSON: ${message}`, [
      { path: "$", keyword: "parse", message },
    ]);
  }

  const value = JSON.parse(text) as unknown;
  assertJsonValue(value);
  assertContract(schemaId, value);
  return value as T;
}

export function canonicalStringify(value: unknown): string {
  assertJsonValue(value);
  const serialized = serializeCanonical(value, "$");
  const byteLength = utf8ByteLength(serialized);
  if (byteLength > MAX_JSON_BYTES) {
    throw new ContractValidationError("Canonical contract JSON exceeds the 1 MiB limit.", [
      { path: "$", keyword: "maxBytes", message: `${byteLength} exceeds ${MAX_JSON_BYTES}.` },
    ]);
  }
  return serialized;
}

export function roundTripContract<T extends JsonValue>(
  schemaId: SchemaId | string,
  value: T,
): T {
  assertContract(schemaId, value);
  return parseContractJson<T>(schemaId, canonicalStringify(value));
}

function validateSchema(
  schema: Schema,
  value: unknown,
  path: string,
  root: JsonRecord,
  issues: ValidationIssue[],
): void {
  if (schema === true) return;
  if (schema === false) {
    addIssue(issues, path, "falseSchema", "The value is forbidden.");
    return;
  }

  const ref = schema.$ref;
  if (typeof ref === "string") {
    const resolved = resolveReference(ref, root);
    if (!resolved) {
      addIssue(issues, path, "$ref", `Unresolved schema reference: ${ref}`);
      return;
    }
    validateSchema(resolved.schema, value, path, resolved.root, issues);
  }

  if (Array.isArray(schema.allOf)) {
    for (const child of schema.allOf) {
      if (isSchema(child)) validateSchema(child, value, path, root, issues);
    }
  }

  if (Array.isArray(schema.anyOf)) {
    const candidates = schema.anyOf.filter(isSchema).map((child) => schemaIssues(child, value, path, root));
    const matches = candidates.filter((candidate) => candidate.length === 0).length;
    if (matches === 0) {
      addIssue(issues, path, "anyOf", "Value matches no allowed schema.");
      issues.push(...shortestIssues(candidates));
    }
  }

  if (Array.isArray(schema.oneOf)) {
    const candidates = schema.oneOf.filter(isSchema).map((child) => schemaIssues(child, value, path, root));
    const matches = candidates.filter((candidate) => candidate.length === 0).length;
    if (matches !== 1) {
      addIssue(issues, path, "oneOf", `Value must match exactly one schema; matched ${matches}.`);
      if (matches === 0) issues.push(...shortestIssues(candidates));
    }
  }

  if (isSchema(schema.not) && schemaMatches(schema.not, value, path, root)) {
    addIssue(issues, path, "not", "Value matches a forbidden schema.");
  }

  if (hasOwn(schema, "const") && !deepEqual(value, schema.const)) {
    addIssue(issues, path, "const", "Value does not equal the required constant.");
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => deepEqual(value, candidate))) {
    addIssue(issues, path, "enum", "Value is not in the closed set.");
  }

  if (typeof schema.type === "string" && !matchesType(schema.type, value)) {
    addIssue(issues, path, "type", `Expected ${schema.type}.`);
    return;
  }

  if (typeof value === "string") validateString(schema, value, path, issues);
  if (typeof value === "number") validateNumber(schema, value, path, issues);
  if (Array.isArray(value)) validateArray(schema, value, path, root, issues);
  if (isRecord(value)) validateObject(schema, value, path, root, issues);
}

function validateString(
  schema: JsonRecord,
  value: string,
  path: string,
  issues: ValidationIssue[],
): void {
  const length = Array.from(value).length;
  if (typeof schema.minLength === "number" && length < schema.minLength) {
    addIssue(issues, path, "minLength", `String length ${length} is below ${schema.minLength}.`);
  }
  if (typeof schema.maxLength === "number" && length > schema.maxLength) {
    addIssue(issues, path, "maxLength", `String length ${length} exceeds ${schema.maxLength}.`);
  }
  if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
    addIssue(issues, path, "pattern", "String does not match the required pattern.");
  }
  if (typeof schema.format === "string" && !matchesFormat(schema.format, value)) {
    addIssue(issues, path, "format", `String does not satisfy ${schema.format}.`);
  }
  if (hasUnpairedSurrogate(value)) {
    addIssue(issues, path, "unicode", "String contains an unpaired Unicode surrogate.");
  }
}

function validateNumber(
  schema: JsonRecord,
  value: number,
  path: string,
  issues: ValidationIssue[],
): void {
  if (!Number.isFinite(value)) addIssue(issues, path, "type", "Number must be finite.");
  if (schema.type === "integer" && !Number.isInteger(value)) {
    addIssue(issues, path, "type", "Number must be an integer.");
  }
  if (typeof schema.minimum === "number" && value < schema.minimum) {
    addIssue(issues, path, "minimum", `${value} is below ${schema.minimum}.`);
  }
  if (typeof schema.maximum === "number" && value > schema.maximum) {
    addIssue(issues, path, "maximum", `${value} exceeds ${schema.maximum}.`);
  }
}

function validateArray(
  schema: JsonRecord,
  value: unknown[],
  path: string,
  root: JsonRecord,
  issues: ValidationIssue[],
): void {
  if (typeof schema.minItems === "number" && value.length < schema.minItems) {
    addIssue(issues, path, "minItems", `Array length ${value.length} is below ${schema.minItems}.`);
  }
  if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
    addIssue(issues, path, "maxItems", `Array length ${value.length} exceeds ${schema.maxItems}.`);
  }
  if (schema.uniqueItems === true) {
    for (let index = 0; index < value.length; index += 1) {
      if (value.slice(0, index).some((candidate) => deepEqual(candidate, value[index]))) {
        addIssue(issues, `${path}[${index}]`, "uniqueItems", "Array item is duplicated.");
      }
    }
  }
  if (isSchema(schema.items)) {
    value.forEach((item, index) => validateSchema(schema.items as Schema, item, `${path}[${index}]`, root, issues));
  }
}

function validateObject(
  schema: JsonRecord,
  value: JsonRecord,
  path: string,
  root: JsonRecord,
  issues: ValidationIssue[],
): void {
  const keys = Object.keys(value);
  for (const key of keys) {
    if (UNSAFE_KEYS.has(key)) addIssue(issues, childPath(path, key), "propertyName", "Unsafe property name.");
  }
  if (typeof schema.minProperties === "number" && keys.length < schema.minProperties) {
    addIssue(issues, path, "minProperties", `Object has fewer than ${schema.minProperties} properties.`);
  }
  if (typeof schema.maxProperties === "number" && keys.length > schema.maxProperties) {
    addIssue(issues, path, "maxProperties", `Object has more than ${schema.maxProperties} properties.`);
  }
  if (Array.isArray(schema.required)) {
    for (const required of schema.required) {
      if (typeof required === "string" && !hasOwn(value, required)) {
        addIssue(issues, path, "required", `Missing required property ${required}.`);
      }
    }
  }

  const properties = isRecord(schema.properties) ? schema.properties : {};
  for (const [key, childSchema] of Object.entries(properties)) {
    if (hasOwn(value, key) && isSchema(childSchema)) {
      validateSchema(childSchema, value[key], childPath(path, key), root, issues);
    }
  }

  if (isSchema(schema.propertyNames)) {
    for (const key of keys) validateSchema(schema.propertyNames, key, childPath(path, key), root, issues);
  }

  for (const key of keys) {
    if (hasOwn(properties, key)) continue;
    if (schema.additionalProperties === false) {
      addIssue(issues, childPath(path, key), "additionalProperties", "Unknown property.");
    } else if (isSchema(schema.additionalProperties)) {
      validateSchema(schema.additionalProperties, value[key], childPath(path, key), root, issues);
    }
  }
}

function runSemanticChecks(schemaId: string, value: unknown, issues: ValidationIssue[]): void {
  if (schemaId === SCHEMA_IDS.stableId && !isAnyStableId(value)) {
    addIssue(issues, "$", "stableId", "Value is not a safe opaque stable ID.");
  }
  const record = isRecord(value) ? value : undefined;
  if (!record) return;

  if (schemaId === SCHEMA_IDS.exactRevision) checkRevision(record, "$", issues);
  if (schemaId === SCHEMA_IDS.pagination) checkPagination(record, "$", issues);
  if (schemaId === SCHEMA_IDS.mutationReceipt) checkReceipt(record, "$", issues);
  if (schemaId === SCHEMA_IDS.secureHandoff) checkHandoff(record, "$", issues);
  if (schemaId === SCHEMA_IDS.stableError) checkStableError(record, "$", issues);
  if (schemaId === SCHEMA_IDS.discovery) checkDiscovery(record, "$", issues);
  if (schemaId === SCHEMA_IDS.providerProfile) checkProviderProfile(record, "$", issues);
  if (schemaId === SCHEMA_IDS.toolDescriptor) checkToolDescriptor(record, "$", issues);
  if (schemaId === SCHEMA_IDS.createProposalInput) checkCreateProposalInput(record, "$", issues);
  if (schemaId === SCHEMA_IDS.changeProposal) checkChangeProposal(record, "$", issues);
  if (schemaId === SCHEMA_IDS.approvalDecision) checkApprovalDecision(record, "$", issues);
  if (schemaId === SCHEMA_IDS.changeSet) checkChangeSet(record, "$", issues);
  if (schemaId === SCHEMA_IDS.auditEvent) checkAuditEvent(record, "$", issues);

  if (schemaId !== SCHEMA_IDS.contractFixture) return;
  if (isRecord(record.revision)) checkRevision(record.revision, "$.revision", issues);
  if (isRecord(record.pagination)) checkPagination(record.pagination, "$.pagination", issues);
  if (isRecord(record.receipt)) checkReceipt(record.receipt, "$.receipt", issues);
  if (isRecord(record.secureHandoff)) checkHandoff(record.secureHandoff, "$.secureHandoff", issues);
  if (isRecord(record.error)) checkStableError(record.error, "$.error", issues);
  if (isRecord(record.discovery)) checkDiscovery(record.discovery, "$.discovery", issues);

  const session = asRecord(record.sessionContext);
  const revision = asRecord(record.revision);
  const contract = record.sourceContract;
  if (contract === "mcp-tools") {
    const citation = asRecord(record.versionCitation);
    equalField(citation, "vaultId", session, "vaultId", "$.versionCitation.vaultId", issues);
    equalField(citation, "workspaceRevisionId", revision, "workspaceRevisionId", "$.versionCitation.workspaceRevisionId", issues);
    const receipt = asRecord(record.receipt);
    equalField(receipt, "newWorkspaceRevisionId", revision, "workspaceRevisionId", "$.receipt.newWorkspaceRevisionId", issues);
    const profiles = Array.isArray(record.providerProfiles) ? record.providerProfiles : [];
    profiles.forEach((profile, index) => checkProviderProfile(asRecord(profile), `$.providerProfiles[${index}]`, issues));
    const ids = profiles.map((profile) => asRecord(profile).profileId);
    if (new Set(ids).size !== 3 || !["generic-text", "openai-chatgpt", "anthropic-claude"].every((id) => ids.includes(id))) {
      addIssue(issues, "$.providerProfiles", "profileSet", "All three provider profiles must occur exactly once.");
    }
  } else if (contract === "graph-context") {
    const citation = asRecord(record.projectionCitation);
    equalField(citation, "sourceWorkspaceRevisionId", revision, "workspaceRevisionId", "$.projectionCitation.sourceWorkspaceRevisionId", issues);
    equalField(citation, "currentWorkspaceRevisionId", revision, "currentWorkspaceRevisionId", "$.projectionCitation.currentWorkspaceRevisionId", issues);
    equalField(citation, "permissionRevisionId", session, "permissionRevisionId", "$.projectionCitation.permissionRevisionId", issues);
    const query = asRecord(record.graphQuery);
    const request = asRecord(query.request);
    const response = asRecord(query.response);
    equalField(request, "op", response, "op", "$.graphQuery.response.op", issues);
    equalField(response, "workspaceRevisionId", revision, "currentWorkspaceRevisionId", "$.graphQuery.response.workspaceRevisionId", issues);
    equalField(response, "sourceWorkspaceRevisionId", citation, "sourceWorkspaceRevisionId", "$.graphQuery.response.sourceWorkspaceRevisionId", issues);
    equalField(response, "graphRevisionId", citation, "projectionRevisionId", "$.graphQuery.response.graphRevisionId", issues);
    if (request.op === "neighbors" && request.depth !== 1) {
      addIssue(issues, "$.graphQuery.request.depth", "operation", "neighbors must be exactly one hop.");
    }
  } else if (contract === "collaboration-security") {
    const guard = asRecord(record.mutationGuard);
    equalField(guard, "baseWorkspaceRevisionId", revision, "workspaceRevisionId", "$.mutationGuard.baseWorkspaceRevisionId", issues);
    const receipt = asRecord(record.receipt);
    equalField(receipt, "oldWorkspaceRevisionId", revision, "workspaceRevisionId", "$.receipt.oldWorkspaceRevisionId", issues);
  }

  if (isRecord(record.discovery)) {
    equalField(record.discovery, "agentSessionId", session, "agentSessionId", "$.discovery.agentSessionId", issues);
    equalField(record.discovery, "providerProfileId", session, "providerProfileId", "$.discovery.providerProfileId", issues);
  }
  if (isRecord(record.secureHandoff)) {
    const binding = asRecord(record.secureHandoff.binding);
    equalField(binding, "subjectId", session, "subjectId", "$.secureHandoff.binding.subjectId", issues);
    equalField(binding, "oauthClientId", session, "oauthClientId", "$.secureHandoff.binding.oauthClientId", issues);
    equalField(binding, "vaultId", session, "vaultId", "$.secureHandoff.binding.vaultId", issues);
  }
}

function checkRevision(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const selector = asRecord(value.selector);
  if (selector.mode === "exact" && selector.workspaceRevisionId !== value.workspaceRevisionId) {
    addIssue(issues, `${path}.workspaceRevisionId`, "exactRevision", "Resolved revision does not match the exact selector.");
  }
}

function checkPagination(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const request = asRecord(value.request);
  const pageInfo = asRecord(value.pageInfo);
  const limit = typeof request.limit === "number" ? request.limit : 50;
  if (typeof pageInfo.returned === "number" && pageInfo.returned > limit) {
    addIssue(issues, `${path}.pageInfo.returned`, "pageLimit", "Returned items exceed the requested/default page limit.");
  }
  if (pageInfo.truncated === false && pageInfo.nextCursor !== null) {
    addIssue(issues, `${path}.pageInfo.nextCursor`, "pagination", "A complete page must not expose a continuation cursor.");
  }
}

function checkReceipt(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  if (value.result === "applied" && typeof value.newWorkspaceRevisionId !== "string") {
    addIssue(issues, path, "receipt", "An applied receipt requires the authoritative new workspace revision.");
  }
  if ((value.result === "conflicted" || value.result === "failed") && hasOwn(value, "newWorkspaceRevisionId")) {
    addIssue(issues, `${path}.newWorkspaceRevisionId`, "receipt", "A non-published outcome cannot name a new workspace revision.");
  }
  const files = Array.isArray(value.files) ? value.files : [];
  const identities = files.map((file) => {
    const record = asRecord(file);
    return `${String(record.fileId)}\u0000${String(record.path)}`;
  });
  if (new Set(identities).size !== identities.length) {
    addIssue(issues, `${path}.files`, "uniqueFiles", "Receipt file identities must be unique.");
  }
}

function checkHandoff(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const handoff = asRecord(value.handoff);
  const statusArgs = asRecord(handoff.statusArgs);
  if (statusArgs.handoffId !== handoff.handoffId) {
    addIssue(issues, `${path}.handoff.statusArgs.handoffId`, "handoffBinding", "Status arguments must bind the same handoff ID.");
  }
}

function checkStableError(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const error = asRecord(value.error);
  if (error.retryable === false && (hasOwn(error, "retryAfterMs") || hasOwn(error, "retryAfterSeconds"))) {
    addIssue(issues, `${path}.error`, "retry", "A non-retryable error cannot include retry timing.");
  }
  if (hasOwn(error, "retryAfterMs") && hasOwn(error, "retryAfterSeconds")) {
    addIssue(issues, `${path}.error`, "retry", "Retry timing must use exactly one unit.");
  }
}

function checkToolDescriptor(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const annotations = asRecord(value.annotations);
  if (annotations.readOnly === true && (annotations.destructive === true || annotations.externalEffect === true)) {
    addIssue(issues, `${path}.annotations`, "toolSafety", "A read-only tool cannot be destructive or have an external effect.");
  }
  if (value.riskClass === "read" && annotations.readOnly !== true) {
    addIssue(issues, `${path}.annotations.readOnly`, "toolSafety", "A read-risk tool must be marked read-only.");
  }
  if (annotations.destructive === true && value.riskClass !== "admin" && value.riskClass !== "apply") {
    addIssue(issues, `${path}.riskClass`, "toolSafety", "A destructive tool must use apply or admin risk.");
  }
}

function checkCreateProposalInput(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const operations = Array.isArray(value.operations) ? value.operations.map(asRecord) : [];
  const operationIds = operations.map((operation) => operation.operationId);
  if (new Set(operationIds).size !== operationIds.length) {
    addIssue(issues, `${path}.operations`, "uniqueOperations", "Proposal operation IDs must be unique.");
  }
  const fileTargets = operations
    .map((operation) => asRecord(operation.file).fileId)
    .filter((fileId): fileId is string => typeof fileId === "string");
  if (new Set(fileTargets).size > 50) {
    addIssue(issues, `${path}.operations`, "affectedFiles", "A proposal cannot affect more than 50 stable files.");
  }
}

function checkChangeProposal(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  if (typeof value.proposalRevision === "number") {
    if (value.proposalRevision === 1 && hasOwn(value, "previousProposalRevision")) {
      addIssue(issues, `${path}.previousProposalRevision`, "proposalRevision", "The first proposal revision cannot name a predecessor.");
    } else if (value.proposalRevision > 1 && value.previousProposalRevision !== value.proposalRevision - 1) {
      addIssue(issues, `${path}.previousProposalRevision`, "proposalRevision", "Previous proposal revision must be the immediate predecessor.");
    }
  }
  const creator = asRecord(value.creator);
  if (hasOwn(creator, "agentSessionId") !== hasOwn(creator, "agentIdentityId")) {
    addIssue(issues, `${path}.creator`, "actorBinding", "Agent identity and session must occur together.");
  }
  checkChronology(value.createdAt, value.expiresAt, `${path}.expiresAt`, issues);
}

function checkApprovalDecision(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  checkChronology(value.decidedAt, value.expiresAt, `${path}.expiresAt`, issues);
}

function checkChangeSet(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const outcome = asRecord(value.outcome);
  const status = value.status;
  if (status === "applied" && outcome.kind !== "receipt") {
    addIssue(issues, `${path}.outcome`, "changeSetOutcome", "An applied change set requires a receipt outcome.");
  }
  if (status === "conflict" && outcome.kind !== "conflict") {
    addIssue(issues, `${path}.outcome`, "changeSetOutcome", "A conflicted change set requires a conflict outcome.");
  }
  if (status === "failed_recoverable" && outcome.kind !== "failure") {
    addIssue(issues, `${path}.outcome`, "changeSetOutcome", "A recoverable failure requires a failure outcome.");
  }
  const nonterminal = new Set(["draft", "validating", "validated", "awaiting_approval", "approved", "preparing", "prepared", "committing"]);
  if (typeof status === "string" && nonterminal.has(status) && hasOwn(value, "outcome")) {
    addIssue(issues, `${path}.outcome`, "changeSetOutcome", "A nonterminal change set cannot claim a terminal outcome.");
  }
  if ((status === "prepared" || status === "committing" || status === "applied") && !hasOwn(value, "preparedRevisionId")) {
    addIssue(issues, `${path}.preparedRevisionId`, "changeSetState", "Prepared and published states require a prepared workspace revision.");
  }
  const actor = asRecord(value.actor);
  if (hasOwn(actor, "agentSessionId") !== hasOwn(actor, "agentIdentityId")) {
    addIssue(issues, `${path}.actor`, "actorBinding", "Agent identity and session must occur together.");
  }
  checkChronology(value.startedAt, value.updatedAt, `${path}.updatedAt`, issues, true);
}

function checkAuditEvent(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const actor = asRecord(value.actor);
  if (hasOwn(actor, "agentSessionId") !== hasOwn(actor, "agentIdentityId")) {
    addIssue(issues, `${path}.actor`, "actorBinding", "Agent identity and session must occur together.");
  }
  if (hasOwn(actor, "oauthClientId") !== hasOwn(actor, "oauthGrantId")) {
    addIssue(issues, `${path}.actor`, "actorBinding", "OAuth client and grant must occur together.");
  }
  const action = asRecord(value.action);
  const hasProposalId = hasOwn(action, "proposalId");
  const hasProposalRevision = hasOwn(action, "proposalRevision");
  if (hasProposalId !== hasProposalRevision) {
    addIssue(issues, `${path}.action`, "auditBinding", "Audit proposal ID and revision must occur together.");
  }
  const affectedFiles = Array.isArray(value.affectedFiles) ? value.affectedFiles.map(asRecord) : [];
  const fileIds = affectedFiles.map((file) => file.fileId);
  if (new Set(fileIds).size !== fileIds.length) {
    addIssue(issues, `${path}.affectedFiles`, "uniqueFiles", "Audit affected file IDs must be unique.");
  }
}

function checkChronology(
  earlier: unknown,
  later: unknown,
  path: string,
  issues: ValidationIssue[],
  allowEqual = false,
): void {
  if (typeof earlier !== "string" || typeof later !== "string") return;
  const earlierMs = Date.parse(earlier);
  const laterMs = Date.parse(later);
  if (laterMs < earlierMs || (!allowEqual && laterMs === earlierMs)) {
    addIssue(issues, path, "chronology", allowEqual ? "Timestamp must not precede its start." : "Expiry must be after its start.");
  }
}

function checkDiscovery(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const tools = Array.isArray(value.tools) ? value.tools : [];
  const unavailable = Array.isArray(value.unavailable) ? value.unavailable : [];
  const toolNames = tools.map((tool) => asRecord(tool).name);
  const unavailableNames = unavailable.map((tool) => asRecord(tool).name);
  if (new Set(toolNames).size !== toolNames.length) {
    addIssue(issues, `${path}.tools`, "uniqueTools", "Available tool names must be unique.");
  }
  if (new Set(unavailableNames).size !== unavailableNames.length) {
    addIssue(issues, `${path}.unavailable`, "uniqueTools", "Unavailable tool names must be unique.");
  }
  if (toolNames.some((name) => unavailableNames.includes(name))) {
    addIssue(issues, path, "availability", "A tool cannot be both available and unavailable.");
  }
  if (!toolNames.includes("get_capabilities")) {
    addIssue(issues, `${path}.tools`, "discovery", "get_capabilities must always be discoverable.");
  }
}

function checkProviderProfile(value: JsonRecord, path: string, issues: ValidationIssue[]): void {
  const allowed: Readonly<Record<string, readonly string[]>> = {
    "generic-text": ["plain-structured-text", "web-handoff", "conservative-annotations"],
    "openai-chatgpt": [
      "registered-oauth-metadata",
      "tool-annotations",
      "optional-ui-resources",
      "provider-conformance-metadata",
    ],
    "anthropic-claude": [
      "registered-oauth-metadata",
      "interactive-connector-presentation",
      "provider-conformance-metadata",
    ],
  };
  const profileId = typeof value.profileId === "string" ? value.profileId : "";
  const adaptations = Array.isArray(value.permittedAdaptations) ? value.permittedAdaptations : [];
  const expected = allowed[profileId];
  if (expected && (
    adaptations.length !== expected.length ||
    !expected.every((adaptation) => adaptations.includes(adaptation))
  )) {
    addIssue(issues, `${path}.permittedAdaptations`, "profileAdaptation", "Profile adaptations do not match the normative closed profile.");
  }
}

function matchesFormat(format: string, value: string): boolean {
  switch (format) {
    case "safe-id":
      return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) && !value.includes("..");
    case "semver":
      return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(value);
    case "opaque-cursor":
      return /^[A-Za-z0-9_-]+$/u.test(value);
    case "iso-date-time":
      return isIsoDateTime(value);
    case "vault-relative-path":
      return isSafeVaultPath(value);
    case "vault-path-pattern":
      return isVaultPathPattern(value);
    case "safe-error-message":
      return isSafeErrorMessage(value);
    case "secure-handoff-url":
      return isSecureHandoffUrl(value);
    default:
      return false;
  }
}

function isIsoDateTime(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)) return false;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return false;
  const normalized = value.includes(".") ? value : value.replace(/Z$/u, ".000Z");
  return new Date(parsed).toISOString() === normalized;
}

function isSafeVaultPath(value: string): boolean {
  if (utf8ByteLength(value) > 1024 || value.startsWith("/") || value.includes("\\")) return false;
  if (/[\u0000-\u001f\u007f]/u.test(value) || value.includes("//")) return false;
  const segments = value.split("/");
  const forbidden = new Set([".", "..", ".git", ".obsidian", ".terraform"]);
  return segments.every(
    (segment) =>
      segment.length > 0 &&
      utf8ByteLength(segment) <= 255 &&
      !forbidden.has(segment.toLowerCase()) &&
      !/[. ]$/u.test(segment),
  );
}

/**
 * VAULTGUARD-125. A permission rule's path pattern exactly as the MCP access adapter admits it
 * (`readPathPattern` in `infrastructure/lambda/mcp/access-tools.ts`): absolute, at most 1024
 * UTF-8 bytes, no backslash and no C0 control or DEL. Wildcard and glob semantics stay with the
 * permission authority, which refuses what it does not support.
 */
function isVaultPathPattern(value: string): boolean {
  if (!value.startsWith("/") || utf8ByteLength(value) > 1024) return false;
  for (const character of value) {
    const codePoint = character.codePointAt(0) as number;
    if (codePoint <= 0x1f || codePoint === 0x7f || codePoint === 0x5c) return false;
  }
  return true;
}

function isSafeErrorMessage(value: string): boolean {
  if (/[\u0000-\u001f\u007f]/u.test(value)) return false;
  return !/(?:bearer\s+|authorization\s*:|x-amz-|AKIA[A-Z0-9]{12,}|sk-[A-Za-z0-9]|(?:access|refresh|session)[-_ ]?token\s*[:=]|private\s+key|recovery\s+code|kms|s3:\/\/|arn:aws|dynamodb|stack\s+trace|\/Users\/|\/home\/)/iu.test(value);
}

function isSecureHandoffUrl(value: string): boolean {
  const match = /^https:\/\/([^/?#]+)(\/[^?#]*)?$/iu.exec(value);
  if (!match) return false;
  const authority = match[1];
  if (authority.includes("@") || authority.includes(":")) return false;
  const host = authority.toLowerCase();
  if (!host.includes(".") || host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) return false;
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(host) || host.includes("..")) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(host)) return false;
  return !/[\\\u0000-\u001f\u007f]/u.test(match[2] ?? "");
}

function resolveReference(
  reference: string,
  currentRoot: JsonRecord,
): { readonly schema: Schema; readonly root: JsonRecord } | undefined {
  const hashIndex = reference.indexOf("#");
  const documentId = hashIndex === -1 ? reference : reference.slice(0, hashIndex);
  const pointer = hashIndex === -1 ? "" : reference.slice(hashIndex + 1);
  const targetRoot = documentId.length === 0 ? currentRoot : schemaDocuments.get(documentId);
  if (!isRecord(targetRoot)) return undefined;
  if (pointer.length === 0) return { schema: targetRoot, root: targetRoot };
  if (!pointer.startsWith("/")) return undefined;
  let current: unknown = targetRoot;
  for (const encoded of pointer.slice(1).split("/")) {
    const part = encoded.replace(/~1/gu, "/").replace(/~0/gu, "~");
    if (!isRecord(current) || !hasOwn(current, part)) return undefined;
    current = current[part];
  }
  return isSchema(current) ? { schema: current, root: targetRoot } : undefined;
}

function schemaMatches(schema: Schema, value: unknown, path: string, root: JsonRecord): boolean {
  return schemaIssues(schema, value, path, root).length === 0;
}

function schemaIssues(schema: Schema, value: unknown, path: string, root: JsonRecord): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  validateSchema(schema, value, path, root, issues);
  return issues;
}

function shortestIssues(candidates: ValidationIssue[][]): ValidationIssue[] {
  return candidates.reduce<ValidationIssue[]>(
    (shortest, candidate) => shortest.length === 0 || candidate.length < shortest.length ? candidate : shortest,
    [],
  );
}

function matchesType(type: string, value: unknown): boolean {
  switch (type) {
    case "array":
      return Array.isArray(value);
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "null":
      return value === null;
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "object":
      return isRecord(value);
    case "string":
      return typeof value === "string";
    default:
      return false;
  }
}

function isRecord(value: unknown): value is JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function asRecord(value: unknown): JsonRecord {
  return isRecord(value) ? value : {};
}

function isSchema(value: unknown): value is Schema {
  return typeof value === "boolean" || isRecord(value);
}

function deepEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((item, index) => deepEqual(item, right[index]));
  }
  if (isRecord(left) && isRecord(right)) {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    return leftKeys.length === rightKeys.length && leftKeys.every(
      (key) => hasOwn(right, key) && deepEqual(left[key], right[key]),
    );
  }
  return false;
}

function equalField(
  left: JsonRecord,
  leftKey: string,
  right: JsonRecord,
  rightKey: string,
  path: string,
  issues: ValidationIssue[],
): void {
  if (left[leftKey] !== right[rightKey]) {
    addIssue(issues, path, "binding", `${leftKey} must match ${rightKey}.`);
  }
}

function addIssue(
  issues: ValidationIssue[],
  path: string,
  keyword: string,
  message: string,
): void {
  issues.push(Object.freeze({ path, keyword, message }));
}

function formatIssue(issue: ValidationIssue): string {
  return `${issue.path} [${issue.keyword}] ${issue.message}`;
}

function childPath(parent: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(key)
    ? `${parent}.${key}`
    : `${parent}[${JSON.stringify(key)}]`;
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function assertJsonValue(
  value: unknown,
  path = "$",
  seen = new Set<object>(),
  depth = 0,
): asserts value is JsonValue {
  if (depth > MAX_JSON_DEPTH) {
    throw new ContractValidationError(`Contract JSON nesting exceeds ${MAX_JSON_DEPTH}.`, [
      { path, keyword: "maxDepth", message: `Nesting exceeds ${MAX_JSON_DEPTH}.` },
    ]);
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    if (typeof value === "string" && hasUnpairedSurrogate(value)) {
      throw new ContractValidationError("Contract JSON contains invalid Unicode.", [
        { path, keyword: "unicode", message: "Unpaired Unicode surrogate." },
      ]);
    }
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new ContractValidationError("Contract JSON contains a non-finite number.", []);
    if (Object.is(value, -0)) throw new ContractValidationError("Negative zero is not canonical JSON.", [
      { path, keyword: "canonicalNumber", message: "Negative zero is ambiguous across serializers." },
    ]);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new ContractValidationError("Contract JSON contains an unsafe integer.", [
        { path, keyword: "safeInteger", message: "Integer exceeds the exact IEEE-754 range." },
      ]);
    }
    return;
  }
  if (typeof value !== "object" || value === undefined) {
    throw new ContractValidationError("Value is not JSON-compatible.", [
      { path, keyword: "type", message: "Unsupported JSON value." },
    ]);
  }
  if (seen.has(value)) throw new ContractValidationError("Contract JSON contains a cycle.", [
    { path, keyword: "cycle", message: "Cyclic values are not JSON-compatible." },
  ]);
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJsonValue(item, `${path}[${index}]`, seen, depth + 1));
  } else if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (UNSAFE_KEYS.has(key)) {
        throw new ContractValidationError("Contract JSON contains an unsafe property.", [
          { path: childPath(path, key), keyword: "propertyName", message: "Unsafe property name." },
        ]);
      }
      assertJsonValue(child, childPath(path, key), seen, depth + 1);
    }
  } else {
    throw new ContractValidationError("Contract JSON must contain plain objects only.", []);
  }
  seen.delete(value);
}

function serializeCanonical(value: unknown, path: string): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (Object.is(value, -0)) throw new ContractValidationError("Negative zero is not canonical JSON.", []);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => serializeCanonical(item, `${path}[${index}]`)).join(",")}]`;
  }
  const record = value as JsonRecord;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${serializeCanonical(record[key], childPath(path, key))}`)
    .join(",")}}`;
}

class StrictJsonScanner {
  private index = 0;

  constructor(private readonly text: string) {}

  scan(): void {
    this.skipWhitespace();
    this.scanValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) this.fail("Unexpected trailing data.");
  }

  private scanValue(depth: number): void {
    if (depth > MAX_JSON_DEPTH) this.fail(`JSON nesting exceeds ${MAX_JSON_DEPTH}.`);
    const char = this.text[this.index];
    if (char === "{") this.scanObject(depth + 1);
    else if (char === "[") this.scanArray(depth + 1);
    else if (char === '"') this.scanString();
    else if (char === "t") this.scanLiteral("true");
    else if (char === "f") this.scanLiteral("false");
    else if (char === "n") this.scanLiteral("null");
    else this.scanNumber();
  }

  private scanObject(depth: number): void {
    this.index += 1;
    this.skipWhitespace();
    const keys = new Set<string>();
    if (this.consume("}")) return;
    while (true) {
      if (this.text[this.index] !== '"') this.fail("Object key must be a string.");
      const key = this.scanString();
      if (UNSAFE_KEYS.has(key)) this.fail(`Unsafe object key ${JSON.stringify(key)}.`);
      if (keys.has(key)) this.fail(`Duplicate object key ${JSON.stringify(key)}.`);
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.fail("Expected ':' after object key.");
      this.skipWhitespace();
      this.scanValue(depth);
      this.skipWhitespace();
      if (this.consume("}")) return;
      if (!this.consume(",")) this.fail("Expected ',' or '}' in object.");
      this.skipWhitespace();
    }
  }

  private scanArray(depth: number): void {
    this.index += 1;
    this.skipWhitespace();
    if (this.consume("]")) return;
    while (true) {
      this.scanValue(depth);
      this.skipWhitespace();
      if (this.consume("]")) return;
      if (!this.consume(",")) this.fail("Expected ',' or ']' in array.");
      this.skipWhitespace();
    }
  }

  private scanString(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const char = this.text[this.index];
      if (char === '"') {
        this.index += 1;
        const raw = this.text.slice(start, this.index);
        try {
          return JSON.parse(raw) as string;
        } catch {
          this.fail("Invalid JSON string escape.");
        }
      }
      if (char === "\\") {
        this.index += 1;
        const escaped = this.text[this.index];
        if (escaped === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(this.text.slice(this.index + 1, this.index + 5))) {
            this.fail("Invalid Unicode escape.");
          }
          this.index += 5;
          continue;
        }
        if (!'"\\/bfnrt'.includes(escaped ?? "")) this.fail("Invalid JSON string escape.");
        this.index += 1;
        continue;
      }
      if (char.charCodeAt(0) <= 0x1f) this.fail("Unescaped control character in string.");
      this.index += 1;
    }
    this.fail("Unterminated JSON string.");
  }

  private scanLiteral(literal: string): void {
    if (this.text.slice(this.index, this.index + literal.length) !== literal) {
      this.fail(`Invalid token; expected ${literal}.`);
    }
    this.index += literal.length;
  }

  private scanNumber(): void {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(this.text.slice(this.index));
    if (!match) this.fail("Invalid JSON value.");
    this.index += match[0].length;
  }

  private skipWhitespace(): void {
    while (/[\u0009\u000a\u000d\u0020]/u.test(this.text[this.index] ?? "")) this.index += 1;
  }

  private consume(expected: string): boolean {
    if (this.text[this.index] !== expected) return false;
    this.index += 1;
    return true;
  }

  private fail(message: string): never {
    throw new Error(`${message} At character ${this.index}.`);
  }
}
