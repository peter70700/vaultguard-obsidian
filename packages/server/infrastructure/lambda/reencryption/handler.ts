/**
 * VaultGuard — Re-encryption Lambda Handler
 *
 * Triggered after user offboarding to re-encrypt all files the revoked user
 * had access to with new DEKs. Performs full application-layer AES-256-GCM
 * re-encryption: decrypt with old DEK → re-encrypt with new DEK → upload.
 *
 * Triggers:
 * - EventBridge event from /auth/revoke (automatic)
 * - POST /re-encryption/trigger (manual admin trigger)
 *
 * Endpoints:
 * - POST /re-encryption/trigger  — Admin: start a re-encryption job
 * - GET  /re-encryption/{jobId}  — Admin: check job status
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command,
} from '@aws-sdk/client-s3';
import {
  KMSClient,
  GenerateDataKeyCommand,
  DecryptCommand,
} from '@aws-sdk/client-kms';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'crypto';
import { TransactWriteCommand } from '@aws-sdk/lib-dynamodb';
import {
  docClient,
  verifyActiveUser,
  requireOrgId,
  pathMatchesPattern,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  generateId,
  isAdmin,
  AuthError,
  ValidationError,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
  PERMISSIONS_TABLE,
  LEASES_TABLE,
  USER_KEYS_TABLE,
} from '../shared/utils';
import {
  acquireRotationLease,
  releaseRotationLease,
  ROTATION_CONTROL_SK,
  type RotationLease,
} from '../shared/rotation-fence';
import { emitSecurityMetric } from '../shared/metrics';

// ─── Configuration ───────────────────────────────────────────────────────────

const S3_BUCKET = process.env.VAULT_BUCKET!;
const S3_PREFIX_BASE = process.env.VAULT_S3_PREFIX || 'vault/';
const KMS_KEY_ID = process.env.KMS_KEY_ID!;
const REENCRYPTION_JOBS_TABLE = process.env.REENCRYPTION_JOBS_TABLE!;
const REGION = process.env.AWS_REGION || 'eu-west-1';

const s3Client = new S3Client({ region: REGION });
const kmsClient = new KMSClient({ region: REGION });

/** VaultGuard encrypted payload format constants */
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const AES_ALGORITHM = 'aes-256-gcm';
const QUERY_MAX_PAGES = 100;
const QUERY_MAX_ITEMS = 10_000;
const MAX_FILE_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = Number(process.env.REENCRYPTION_RETRY_BASE_DELAY_MS ?? 250);

// ─── Types ───────────────────────────────────────────────────────────────────

interface ReEncryptionJob {
  jobId: string;
  orgId: string;
  targetUserId: string;
  triggeredBy: string;
  status: 'pending' | 'in_progress' | 'completed' | 'partial' | 'failed';
  totalFiles: number;
  processedFiles: number;
  failedFiles: number;
  errors: string[];
  scopeResults?: ReEncryptionScopeResult[];
  rotatedScopes?: AffectedVaultScope[];
  rolledBackScopes?: AffectedVaultScope[];
  startedAt: string;
  completedAt?: string;
  /** TTL: auto-delete 90 days after completion */
  expiresAtTtl?: number;
}

/** A recovered old DEK from a revoked lease */
interface RecoveredDek {
  vaultId?: string;
  scope: string;
  plaintextKey: Buffer;
}

interface AffectedVaultScope {
  vaultId: string;
  scope: string;
}

interface PreparedScopeKey {
  plaintextKey: Buffer;
  encryptedDataKey: string;
  previousItem?: Record<string, unknown>;
  /**
   * Freshly generated UUID v4 (per-rotation) that stays with this DEK for life
   * (ACTIVE → ROTATED#<ts>). Phase 7 cross-DEK restore looks up historical DEKs
   * via the `keyId-index` GSI on `user_keys` using this id.
   */
  newKeyId: string;
}

interface ReEncryptionScopeResult extends AffectedVaultScope {
  status: 'committed' | 'rolled_back' | 'recovery_required';
  totalFiles: number;
  processedFiles: number;
  failedFiles: number;
  reason?: string;
}

interface ReEncryptionPlan extends AffectedVaultScope {
  oldKey: { key: Buffer; keyId: string };
  newKey: PreparedScopeKey;
  s3Keys: string[];
}

/**
 * Copy KMS plaintext into the caller-owned buffer and immediately wipe the SDK
 * response view. The returned buffer must itself be wiped by its owner in a
 * `finally` block.
 */
export function takeAndWipeKmsPlaintext(plaintext: Uint8Array): Buffer {
  const owned = Buffer.from(plaintext);
  plaintext.fill(0);
  return owned;
}

function wipeBuffers(buffers: Iterable<Buffer | null | undefined>): void {
  for (const buffer of buffers) buffer?.fill(0);
}

function boundedJobError(message: string): string {
  return message.replace(/[\r\n\t]+/g, ' ').slice(0, 500);
}

async function queryAllPages(
  input: Record<string, unknown> & { TableName: string },
  label: string,
): Promise<Record<string, unknown>[]> {
  const items: Record<string, unknown>[] = [];
  let exclusiveStartKey: Record<string, unknown> | undefined;
  for (let page = 1; page <= QUERY_MAX_PAGES; page++) {
    const result = await docClient.send(
      new QueryCommand({
        ...input,
        ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {}),
      } as never),
    );
    for (const item of result.Items ?? []) {
      items.push(item as Record<string, unknown>);
      if (items.length > QUERY_MAX_ITEMS) {
        throw new Error(
          `${label} exceeded the fail-closed ${QUERY_MAX_ITEMS}-row discovery ceiling`,
        );
      }
    }
    exclusiveStartKey = result.LastEvaluatedKey as Record<string, unknown> | undefined;
    if (!exclusiveStartKey) return items;
  }
  throw new Error(`${label} exceeded the fail-closed ${QUERY_MAX_PAGES}-page discovery ceiling`);
}

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function handler(
  event: APIGatewayProxyEvent | EventBridgeEvent
): Promise<APIGatewayProxyResult | void> {
  // EventBridge invocation (from /auth/revoke)
  if (isEventBridgeEvent(event)) {
    await handleEventBridgeTrigger(event);
    return;
  }

  // API Gateway invocation
  const apiEvent = event as APIGatewayProxyEvent;
  const requestId = apiEvent.requestContext?.requestId || generateId();
  const method = apiEvent.httpMethod?.toUpperCase();
  const resource = apiEvent.resource || apiEvent.path;

  try {
    switch (true) {
      case method === 'POST' && resource === '/re-encryption/trigger':
        return await handleManualTrigger(apiEvent, requestId);

      case method === 'GET' && /\/re-encryption\/[^/]+$/.test(resource):
        return await handleGetJobStatus(apiEvent, requestId);

      default:
        return formatError(404, `Route not found: ${method} ${resource}`, requestId);
    }
  } catch (err) {
    if (err instanceof AuthError) {
      return formatError(err.statusCode, err.message, requestId, err.code);
    }
    if (err instanceof ValidationError) {
      return formatError(err.statusCode, err.message, requestId);
    }
    console.error('[REENCRYPTION_HANDLER_ERROR]', (err as Error).message);
    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── EventBridge Types ──────────────────────────────────────────────────────

interface EventBridgeEvent {
  source: string;
  'detail-type': string;
  detail: {
    targetUserId: string;
    orgId: string;
    triggeredBy: string;
    jobId?: string;
    reason: string;
  };
}

function isEventBridgeEvent(event: unknown): event is EventBridgeEvent {
  return (
    typeof event === 'object' &&
    event !== null &&
    'source' in event &&
    'detail-type' in event &&
    (event as EventBridgeEvent).source === 'vaultguard.auth'
  );
}

// ─── EventBridge Trigger ────────────────────────────────────────────────────

async function handleEventBridgeTrigger(event: EventBridgeEvent): Promise<void> {
  const { targetUserId, orgId, triggeredBy, jobId } = event.detail;
  console.info(`[REENCRYPTION] EventBridge trigger: re-encrypt files for revoked user ${targetUserId}`);
  await executeReEncryptionJob(targetUserId, orgId, triggeredBy, jobId);
}

// ─── POST /re-encryption/trigger ────────────────────────────────────────────

async function handleManualTrigger(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const admin = await verifyActiveUser(event);
  const orgId = requireOrgId(admin);

  if (!isAdmin(admin)) {
    throw new AuthError('Admin privileges required', 403);
  }

  const body = parseBody(event);
  validateRequiredFields(body, ['targetUserId']);

  const targetUserId = body.targetUserId as string;
  const jobId = await executeReEncryptionJob(targetUserId, orgId, admin.userId);

  return formatSuccess(
    202,
    { message: 'Re-encryption job started', jobId, targetUserId },
    requestId
  );
}

// ─── GET /re-encryption/{jobId} ─────────────────────────────────────────────

async function handleGetJobStatus(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const admin = await verifyActiveUser(event);
  const orgId = requireOrgId(admin);

  if (!isAdmin(admin)) {
    throw new AuthError('Admin privileges required', 403);
  }

  const jobId = event.pathParameters?.jobId;
  if (!jobId) {
    throw new ValidationError('Missing jobId path parameter');
  }

  const result = await docClient.send(
    new GetCommand({
      TableName: REENCRYPTION_JOBS_TABLE,
      Key: { jobId },
    })
  );

  if (!result.Item) {
    return formatError(404, `Re-encryption job not found: ${jobId}`, requestId);
  }
  if (result.Item.orgId !== orgId) {
    throw new AuthError('Re-encryption job not found', 404);
  }

  return formatSuccess(200, { job: result.Item }, requestId);
}

// ─── Core Re-encryption Logic ───────────────────────────────────────────────

/**
 * Executes a full re-encryption job:
 * 1. Recover old DEKs from the revoked user's lease records
 * 2. Query permissions to find affected paths
 * 3. List S3 objects matching those paths
 * 4. For each file: decrypt with old DEK → re-encrypt with new DEK → upload
 * 5. Track progress in ReEncryptionJobsTable
 */
async function executeReEncryptionJob(
  targetUserId: string,
  orgId: string,
  triggeredBy: string,
  presetJobId?: string,
): Promise<string> {
  const jobId = presetJobId || generateId();
  const now = new Date().toISOString();

  const job: ReEncryptionJob = {
    jobId,
    orgId,
    targetUserId,
    triggeredBy,
    status: 'in_progress',
    totalFiles: 0,
    processedFiles: 0,
    failedFiles: 0,
    errors: [],
    startedAt: now,
  };

  await docClient.send(
    new PutCommand({ TableName: REENCRYPTION_JOBS_TABLE, Item: job })
  );

  let oldDeks: RecoveredDek[] = [];
  let plans: ReEncryptionPlan[] = [];
  const acquiredLeases: RotationLease[] = [];
  const scopeResults: ReEncryptionScopeResult[] = [];
  const errors: string[] = [];
  try {
    // Step 1: Recover old DEKs from the user's lease records. These cover
    // legacy deployments and tell us which vaults the revoked user actually
    // held usable keys for.
    oldDeks = await recoverOldDeks(targetUserId, orgId);

    // Step 2: Find affected vaults. The current plugin uses one active key
    // per bound vault, so any revoked access inside a vault rotates that
    // vault's /** key and re-encrypts the vault contents with the new key.
    const affectedScopes = await getAffectedVaultScopes(targetUserId, orgId, oldDeks);

    if (affectedScopes.length === 0) {
      await updateJobStatus(jobId, 'completed', { totalFiles: 0, completedAt: new Date().toISOString() });
      return jobId;
    }

    // Step 3: Rotate each affected vault/scope key and list matching objects.
    // Plan sequentially so every acquired plaintext key is either attached to
    // `plans` (and wiped by the outer finally) or wiped by the local catch.
    // Promise.all made already-resolved sibling plans unreachable when any
    // other scope rejected, leaving their DEKs live in a warm Lambda process.
    const orderedScopes = [...affectedScopes].sort((a, b) =>
      `${a.vaultId}\u0000${a.scope}`.localeCompare(`${b.vaultId}\u0000${b.scope}`)
    );
    for (const affected of orderedScopes) {
      let oldKey: { key: Buffer; keyId: string } | null = null;
      let newKey: PreparedScopeKey | null = null;
      try {
        const lease = await acquireRotationLease({
          orgId,
          vaultId: affected.vaultId,
          scope: affected.scope,
          jobId,
        });
        acquiredLeases.push(lease);
        oldKey = await resolveOldScopeKey(orgId, affected.vaultId, affected.scope, oldDeks);
        newKey = await prepareRotatedScopeDataKey(orgId, affected.vaultId, affected.scope, jobId);
        const s3Keys = await listAffectedS3Objects(orgId, affected.vaultId, [affected.scope]);
        plans.push({ ...affected, oldKey, newKey, s3Keys });
        oldKey = null;
        newKey = null;
      } catch (error) {
        oldKey?.key.fill(0);
        newKey?.plaintextKey.fill(0);
        throw error;
      }
    }

    const totalFiles = plans.reduce((sum, plan) => sum + plan.s3Keys.length, 0);

    await updateJobStatus(jobId, 'in_progress', { totalFiles });

    // Step 4: Re-encrypt each file
    let processedFiles = 0;
    let failedFiles = 0;

    for (const plan of plans) {
      const prefix = vaultS3Prefix(orgId, plan.vaultId);
      const processedPlanKeys: string[] = [];
      let planFailed = false;
      let planFailedFiles = 0;

      for (const s3Key of plan.s3Keys) {
        try {
          const vaultPath = '/' + s3Key.replace(prefix, '');
          await reEncryptFileWithRetry(
            s3Key,
            vaultPath,
            orgId,
            plan.vaultId,
            plan.oldKey.key,
            plan.newKey.plaintextKey,
            plan.newKey.newKeyId,
          );
          processedPlanKeys.push(s3Key);
          processedFiles++;
        } catch (err) {
          planFailed = true;
          planFailedFiles++;
          failedFiles++;
          const errMsg = boundedJobError(`${s3Key}: ${err instanceof Error ? err.message : String(err)}`);
          if (errors.length < 100) errors.push(errMsg);
          console.error(`[REENCRYPTION] Failed: ${errMsg}`);
        }

        if ((processedFiles + failedFiles) % 10 === 0) {
          await updateJobStatus(jobId, 'in_progress', { processedFiles, failedFiles, errors });
        }
      }

      if (planFailed) {
        let rollbackFailed = false;
        for (const s3Key of processedPlanKeys) {
          try {
            const vaultPath = '/' + s3Key.replace(prefix, '');
            // Rollback: re-encrypt back to the OLD key, so the object's
            // `vaultguard-key-id` Metadata should reflect the OLD keyId
            // (the DEK the file is now wrapped with after rollback).
            await reEncryptFileWithRetry(
              s3Key,
              vaultPath,
              orgId,
              plan.vaultId,
              plan.newKey.plaintextKey,
              plan.oldKey.key,
              plan.oldKey.keyId,
            );
            processedFiles--;
          } catch (rollbackErr) {
            rollbackFailed = true;
            const errMsg = boundedJobError(`${s3Key}: rollback failed: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`);
            if (errors.length < 100) errors.push(errMsg);
            console.error(`[REENCRYPTION] ${errMsg}`);
          }
        }
        scopeResults.push({
          vaultId: plan.vaultId,
          scope: plan.scope,
          status: rollbackFailed ? 'recovery_required' : 'rolled_back',
          totalFiles: plan.s3Keys.length,
          processedFiles: rollbackFailed ? processedPlanKeys.length : 0,
          failedFiles: planFailedFiles,
          reason: rollbackFailed
            ? 'One or more conditional rollbacks failed; the prepared key record was retained for recovery.'
            : 'At least one forward re-encryption failed; successful rewrites were rolled back.',
        });
      } else {
        try {
          await commitRotatedScopeDataKey(
            orgId,
            plan.vaultId,
            plan.scope,
            triggeredBy,
            jobId,
            plan.newKey,
          );
          scopeResults.push({
            vaultId: plan.vaultId,
            scope: plan.scope,
            status: 'committed',
            totalFiles: plan.s3Keys.length,
            processedFiles: plan.s3Keys.length,
            failedFiles: 0,
          });
        } catch (commitError) {
          const commitMessage = boundedJobError(
            `Vault ${plan.vaultId} scope ${plan.scope}: key commit failed: ${
              commitError instanceof Error ? commitError.message : String(commitError)
            }`,
          );
          if (errors.length < 100) errors.push(commitMessage);
          console.error(`[REENCRYPTION] ${commitMessage}`);

          let rollbackFailed = false;
          for (const s3Key of processedPlanKeys) {
            try {
              const vaultPath = '/' + s3Key.replace(prefix, '');
              await reEncryptFileWithRetry(
                s3Key,
                vaultPath,
                orgId,
                plan.vaultId,
                plan.newKey.plaintextKey,
                plan.oldKey.key,
                plan.oldKey.keyId,
              );
              processedFiles--;
            } catch (rollbackError) {
              rollbackFailed = true;
              const rollbackMessage = boundedJobError(
                `${s3Key}: rollback after commit failure failed: ${
                  rollbackError instanceof Error ? rollbackError.message : String(rollbackError)
                }`,
              );
              if (errors.length < 100) errors.push(rollbackMessage);
              console.error(`[REENCRYPTION] ${rollbackMessage}`);
            }
          }
          scopeResults.push({
            vaultId: plan.vaultId,
            scope: plan.scope,
            status: rollbackFailed ? 'recovery_required' : 'rolled_back',
            totalFiles: plan.s3Keys.length,
            processedFiles: rollbackFailed ? processedPlanKeys.length : 0,
            failedFiles: 0,
            reason: rollbackFailed
              ? 'The conditional key commit and one or more rollbacks failed; the prepared key record was retained.'
              : 'The conditional key commit failed; rewritten objects were rolled back.',
          });
        }
      }
    }

    // Finalize with scope truth. A partial rotation must never be reported as
    // completed while any scope still uses (or may use) the revoked DEK.
    const rotatedScopes = scopeResults
      .filter((result) => result.status === 'committed')
      .map(({ vaultId, scope }) => ({ vaultId, scope }));
    const rolledBackScopes = scopeResults
      .filter((result) => result.status !== 'committed')
      .map(({ vaultId, scope }) => ({ vaultId, scope }));
    const finalStatus = finalizeReEncryptionStatus(scopeResults);
    const completedAt = new Date().toISOString();
    const ttl = Math.floor(new Date(completedAt).getTime() / 1000) + 90 * 24 * 60 * 60;

    await updateJobStatus(jobId, finalStatus, {
      processedFiles,
      failedFiles,
      errors,
      scopeResults,
      rotatedScopes,
      rolledBackScopes,
      completedAt,
      expiresAtTtl: ttl,
    });

    await logAudit({
      userId: triggeredBy,
      orgId,
      action: 'reencryption.completed',
      resourcePath: `/re-encryption/${jobId}`,
      outcome: finalStatus === 'completed' ? 'success' : 'error',
      metadata: {
        jobId,
        targetUserId,
        totalFiles,
        processedFiles,
        failedFiles,
        finalStatus,
        scopeResults,
        rotatedScopes,
        rolledBackScopes,
      },
    });

    // A job that ends anything other than `completed` left files readable with
    // the offboarded user's old DEK. Awaited, not fire-and-forget: this is the
    // rare/critical path the metrics module documents, its alarm fires at >= 1,
    // and losing the data point would silently restore the pre-fix behaviour
    // where a partial rotation looked exactly like a successful one.
    if (finalStatus !== 'completed') {
      await emitSecurityMetric('ReEncryptionIncomplete');
    }

    console.info(
      `[REENCRYPTION] Job ${jobId} ${finalStatus}: ${processedFiles} re-encrypted, ` +
      `${failedFiles} failed, ${rolledBackScopes.length} scope(s) incomplete`,
    );
    return jobId;
  } catch (err) {
    await updateJobStatus(jobId, 'failed', {
      errors: [boundedJobError(err instanceof Error ? err.message : String(err)), ...errors].slice(0, 100),
      scopeResults,
      completedAt: new Date().toISOString(),
    });
    // Same signal as the finalize path above. A job that dies mid-flight is the
    // most incomplete outcome there is, and it is also the path that reaches
    // the async retry/DLQ machinery — emit before rethrowing so the page fires
    // even when every retry ultimately fails.
    await emitSecurityMetric('ReEncryptionIncomplete');
    throw err;
  } finally {
    // Recovered and freshly generated DEKs are process-memory secrets. Wipe
    // them on every exit, including discovery, S3, rollback, job-status, and
    // commit failures. The previous success-only cleanup leaked them in warm
    // Lambda containers whenever an exception escaped before finalization.
    wipeBuffers(oldDeks.map((dek) => dek.plaintextKey));
    wipeBuffers(plans.flatMap((plan) => [plan.oldKey.key, plan.newKey.plaintextKey]));
    for (const lease of acquiredLeases.reverse()) {
      try {
        await releaseRotationLease(lease);
      } catch (releaseError) {
        console.warn(
          `[REENCRYPTION] Rotation lease release failed for vault ${lease.vaultId} scope ${lease.scope}; it will expire automatically:`,
          releaseError,
        );
      }
    }
  }
}

export function finalizeReEncryptionStatus(
  scopeResults: Array<Pick<ReEncryptionScopeResult, 'status'>>,
): ReEncryptionJob['status'] {
  const committed = scopeResults.filter((result) => result.status === 'committed').length;
  if (committed === scopeResults.length) return 'completed';
  return committed === 0 ? 'failed' : 'partial';
}

// ─── DEK Recovery ───────────────────────────────────────────────────────────

/**
 * Recovers plaintext DEKs from a revoked user's lease records.
 * Each lease stores an encrypted data key blob; we use KMS Decrypt
 * with the original encryption context to recover the plaintext DEK.
 */
async function recoverOldDeks(userId: string, orgId: string): Promise<RecoveredDek[]> {
  const leases = await queryAllPages(
    {
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':uid': userId, ':orgId': orgId },
    },
    'revoked-user lease discovery',
  );
  const recovered: RecoveredDek[] = [];
  const seenScopes = new Set<string>();

  // Sort by issuedAt descending to get the most recent lease per scope
  leases.sort((a, b) => {
    const aTime = a.issuedAt as string || '';
    const bTime = b.issuedAt as string || '';
    return bTime.localeCompare(aTime);
  });

  for (const lease of leases) {
    const scope = (lease.scope as string) || '/**';
    const vaultId = lease.vaultId as string | undefined;
    const encryptedDataKey = lease.encryptedDataKey as string | undefined;
    const sessionId = lease.sessionId as string;
    const seenKey = `${vaultId || '__legacy__'}:${scope}`;

    // Only need one DEK per scope (most recent)
    if (seenScopes.has(seenKey) || !encryptedDataKey) continue;
    seenScopes.add(seenKey);

    try {
      const decryptResponse = await kmsClient.send(
        new DecryptCommand({
          CiphertextBlob: Buffer.from(encryptedDataKey, 'base64'),
          EncryptionContext: {
            orgId,
            ...(vaultId ? { vaultId } : {}),
            scope,
            purpose: 'vault-scope-dek',
          },
        })
      );

      if (decryptResponse.Plaintext) {
        recovered.push({
          ...(vaultId ? { vaultId } : {}),
          scope,
          plaintextKey: takeAndWipeKmsPlaintext(decryptResponse.Plaintext),
        });
      }
    } catch {
      try {
        const decryptResponse = await kmsClient.send(
          new DecryptCommand({
            CiphertextBlob: Buffer.from(encryptedDataKey, 'base64'),
            EncryptionContext: {
              userId,
              sessionId,
              scope,
              purpose: 'vault-decryption',
            },
          })
        );

        if (decryptResponse.Plaintext) {
          recovered.push({
            ...(vaultId ? { vaultId } : {}),
            scope,
            plaintextKey: takeAndWipeKmsPlaintext(decryptResponse.Plaintext),
          });
        }
      } catch {
        // KMS Decrypt may fail if the encryption context doesn't match
        // (e.g., older leases before scope was added). Try without scope.
        try {
          const decryptResponse = await kmsClient.send(
            new DecryptCommand({
              CiphertextBlob: Buffer.from(encryptedDataKey, 'base64'),
              EncryptionContext: {
                userId,
                sessionId,
                purpose: 'vault-decryption',
              },
            })
          );

          if (decryptResponse.Plaintext) {
            recovered.push({
              ...(vaultId ? { vaultId } : {}),
              scope,
              plaintextKey: takeAndWipeKmsPlaintext(decryptResponse.Plaintext),
            });
          }
        } catch {
          console.warn(`[REENCRYPTION] Could not recover DEK for scope '${scope}', lease ${lease.leaseId}`);
        }
      }
    }
  }

  console.info(`[REENCRYPTION] Recovered ${recovered.length} DEKs from ${leases.length} leases`);
  return recovered;
}

// ─── AES-256-GCM Operations ────────────────────────────────────────────────

/**
 * Decrypt a VaultGuard-format encrypted payload.
 * Format: [IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)]
 */
export function aesDecrypt(payload: Buffer, key: Buffer): Buffer {
  if (payload.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error(`Payload too short for decryption: ${payload.length} bytes`);
  }

  const iv = payload.subarray(0, IV_LENGTH);
  const authTag = payload.subarray(payload.length - AUTH_TAG_LENGTH);
  const ciphertext = payload.subarray(IV_LENGTH, payload.length - AUTH_TAG_LENGTH);

  const decipher = createDecipheriv(AES_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const updated = decipher.update(ciphertext);
  let finalized: Buffer | null = null;
  try {
    finalized = decipher.final();
    const decrypted = Buffer.alloc(updated.length + finalized.length);
    updated.copy(decrypted, 0);
    finalized.copy(decrypted, updated.length);
    return decrypted;
  } finally {
    // `decipher.update()` can yield unauthenticated plaintext before final()
    // verifies the GCM tag. Keep explicit ownership so both success and tag
    // failure wipe every transient plaintext buffer.
    updated.fill(0);
    finalized?.fill(0);
  }
}

/**
 * Encrypt plaintext into VaultGuard format with a new random IV.
 * Returns: [IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)]
 */
export function aesEncrypt(plaintext: Buffer, key: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(AES_ALGORITHM, key, iv);

  const updated = cipher.update(plaintext);
  let finalized: Buffer | null = null;
  let authTag: Buffer | null = null;
  try {
    finalized = cipher.final();
    authTag = cipher.getAuthTag();

    // Pack exactly like the plugin Web Crypto path: [IV][ciphertext || tag].
    const encryptedLength = updated.length + finalized.length;
    const result = Buffer.alloc(IV_LENGTH + AUTH_TAG_LENGTH + encryptedLength);
    iv.copy(result, 0);
    updated.copy(result, IV_LENGTH);
    finalized.copy(result, IV_LENGTH + updated.length);
    authTag.copy(result, IV_LENGTH + encryptedLength);
    return result;
  } finally {
    iv.fill(0);
    updated.fill(0);
    finalized?.fill(0);
    authTag?.fill(0);
  }
}

// ─── File Re-encryption ────────────────────────────────────────────────────

/**
 * Re-encrypt a single S3 file with full application-layer AES-256-GCM re-encryption.
 *
 * Process:
 * 1. Download the encrypted file from S3
 * 2. Decrypt the content using the previous vault DEK
 * 3. Re-encrypt the content with the rotated vault DEK
 * 4. Upload the re-encrypted content to S3 with audit metadata
 */
async function reEncryptFile(
  s3Key: string,
  vaultPath: string,
  orgId: string,
  vaultId: string,
  oldKey: Buffer,
  newKey: Buffer,
  newKeyId: string,
): Promise<void> {
  // Download encrypted file
  const getResponse = await s3Client.send(
    new GetObjectCommand({ Bucket: S3_BUCKET, Key: s3Key })
  );

  const body = await getResponse.Body?.transformToByteArray();
  if (!body || body.length === 0) {
    throw new Error('Empty file body');
  }
  if (!getResponse.ETag) {
    throw new Error(`S3 did not return an ETag for ${vaultPath}; refusing an unfenced overwrite`);
  }

  const encryptedPayload = Buffer.from(body);
  let plaintext: Buffer | null = null;
  let reEncrypted: Buffer | null = null;
  try {
    try {
      plaintext = aesDecrypt(encryptedPayload, oldKey);
    } catch (err) {
      throw new Error(`AES decryption failed for ${vaultPath}: ${err instanceof Error ? err.message : String(err)}`);
    }

    reEncrypted = aesEncrypt(plaintext, newKey);

    await s3Client.send(
      new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: s3Key,
        IfMatch: getResponse.ETag,
        Body: reEncrypted,
        ContentType: getResponse.ContentType || 'application/octet-stream',
        Metadata: {
        // SPREAD FIRST: inherit any unrelated S3 metadata from the pre-rotation
        // GET (e.g. `modified-by`, `modified-at`) so the re-encrypted object
        // retains its provenance.
        ...getResponse.Metadata,
        'x-vaultguard-reencrypted': 'true',
        'x-vaultguard-reencryption-time': new Date().toISOString(),
        'x-vaultguard-vault-id': vaultId,
        'x-vaultguard-key-scope': '/**',
        // OVERRIDE AFTER THE SPREAD: the pre-rotation Metadata MAY have carried
        // a stale `vaultguard-key-id` (the OLD DEK's keyId). Phase 7's restore
        // endpoint matches noncurrent versions to DEKs by this attribute, so it
        // MUST reflect the DEK the file is now wrapped with (the NEW one). The
        // explicit assignment AFTER the spread guarantees override semantics.
        // See: 06-02-PLAN.md "spread-then-override invariant", T-06-02-02.
        'vaultguard-key-id': newKeyId,
        },
      })
    );
  } finally {
    plaintext?.fill(0);
    reEncrypted?.fill(0);
    encryptedPayload.fill(0);
  }
}

async function reEncryptFileWithRetry(
  ...args: Parameters<typeof reEncryptFile>
): Promise<void> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_FILE_ATTEMPTS; attempt++) {
    try {
      await reEncryptFile(...args);
      return;
    } catch (error) {
      lastError = error;
      if (attempt < MAX_FILE_ATTEMPTS) {
        await new Promise((resolve) => setTimeout(resolve, RETRY_BASE_DELAY_MS * attempt));
      }
    }
  }
  throw lastError;
}

// ─── Vault/Key Discovery ─────────────────────────────────────────────────────

function vaultS3Prefix(orgId: string, vaultId: string): string {
  if (!orgId || !vaultId) {
    throw new Error('CRITICAL: vaultS3Prefix called without orgId+vaultId');
  }
  return `${S3_PREFIX_BASE}${orgId}/${vaultId}/`;
}

function encodedScope(scope: string): string {
  return Buffer.from(scope, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function scopeKeyPk(orgId: string, scope: string, vaultId?: string): string {
  const scopePart = encodedScope(scope);
  if (vaultId) {
    return `ORG#${orgId}#VAULT#${vaultId}#SCOPE#${scopePart}`;
  }
  return `ORG#${orgId}#SCOPE#${scopePart}`;
}

// Exported so Phase 7's restore endpoint and the Plan 06-03 EncryptionContext
// preservation test can reconstruct the KMS EncryptionContext from a
// GSI-projected user_keys row (orgId + scope + vaultId). Pure function with
// no I/O — safe to widen surface.
export function scopeKmsContext(orgId: string, scope: string, vaultId?: string): Record<string, string> {
  return {
    orgId,
    ...(vaultId ? { vaultId } : {}),
    scope,
    purpose: 'vault-scope-dek',
  };
}

async function getAffectedVaultScopes(
  userId: string,
  orgId: string,
  oldDeks: RecoveredDek[]
): Promise<AffectedVaultScope[]> {
  const scopesByVault = new Map<string, Set<string>>();

  const add = (vaultId: unknown, scope: unknown): void => {
    if (typeof vaultId !== 'string' || !vaultId) return;
    const vaultScopes = scopesByVault.get(vaultId) ?? new Set<string>();
    // Current plugin crypto uses one active key per vault. Rotate the vault
    // root key for any affected path so every client can keep decrypting with
    // the single active vault lease it already understands.
    vaultScopes.add('/**');
    scopesByVault.set(vaultId, vaultScopes);
  };

  for (const dek of oldDeks) {
    add(dek.vaultId, dek.scope);
  }

  const userItems = await queryAllPages(
    {
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':uid': userId, ':orgId': orgId },
    },
    'user permission discovery',
  );

  for (const item of userItems) {
    if (item.pathPattern && item.effect === 'allow') {
      add(item.vaultId, item.pathPattern);
    }
  }

  const wildcardItems = await queryAllPages(
    {
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':uid': '*', ':orgId': orgId },
    },
    'wildcard permission discovery',
  );

  for (const item of wildcardItems) {
    if (item.pathPattern && item.effect === 'allow') {
      add(item.vaultId, item.pathPattern);
    }
  }

  return Array.from(scopesByVault.entries()).flatMap(([vaultId, scopes]) =>
    Array.from(scopes).map((scope) => ({ vaultId, scope }))
  );
}

export async function getActiveScopeDataKey(
  orgId: string,
  vaultId: string | undefined,
  scope: string
): Promise<{ key: Buffer; keyId: string } | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk: scopeKeyPk(orgId, scope, vaultId), sk: 'ACTIVE' },
      ConsistentRead: true,
    })
  );

  const item = result.Item as
    | { encryptedDataKey?: string; status?: string; keyId?: string }
    | undefined;
  if (!item?.encryptedDataKey || item.status !== 'active') {
    return null;
  }

  const decryptResponse = await kmsClient.send(
    new DecryptCommand({
      CiphertextBlob: Buffer.from(item.encryptedDataKey, 'base64'),
      EncryptionContext: scopeKmsContext(orgId, scope, vaultId),
    })
  );

  if (!decryptResponse.Plaintext) {
    throw new Error(`KMS Decrypt did not return key material for vault ${vaultId || '(legacy)'}`);
  }

  // Backwards-compat: rows written before Phase 6 don't yet have `keyId`.
  // Use `'legacy'` sentinel; the backfill script populates real UUIDs.
  // Phase 7's restore endpoint will fall back to current-ACTIVE-DEK + warning
  // audit when the keyId on an S3 object is `'legacy'` or absent.
  const keyId = typeof item.keyId === 'string' && item.keyId.length > 0 ? item.keyId : 'legacy';

  return { key: takeAndWipeKmsPlaintext(decryptResponse.Plaintext), keyId };
}

async function resolveOldScopeKey(
  orgId: string,
  vaultId: string,
  scope: string,
  oldDeks: RecoveredDek[]
): Promise<{ key: Buffer; keyId: string }> {
  const activeVaultKey = await getActiveScopeDataKey(orgId, vaultId, scope);
  if (activeVaultKey) return activeVaultKey;

  const legacyActiveKey = await getActiveScopeDataKey(orgId, undefined, scope);
  if (legacyActiveKey) return legacyActiveKey;

  const recovered = oldDeks.find((dek) => dek.vaultId === vaultId && dek.scope === scope)
    ?? oldDeks.find((dek) => !dek.vaultId && dek.scope === scope);
  if (recovered) {
    // RecoveredDek is pre-keyId (it comes from a revoked lease, not from user_keys);
    // tag with 'legacy' so downstream metadata writers know there's no canonical
    // keyId to record for this DEK. Phase 7 will treat 'legacy' as a fallback signal.
    return { key: Buffer.from(recovered.plaintextKey), keyId: 'legacy' };
  }

  throw new Error(`No decryptable active key for vault ${vaultId} scope ${scope}`);
}

async function prepareRotatedScopeDataKey(
  orgId: string,
  vaultId: string,
  scope: string,
  jobId: string,
): Promise<PreparedScopeKey> {
  const pk = scopeKeyPk(orgId, scope, vaultId);
  const currentResult = await docClient.send(
    new GetCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk, sk: 'ACTIVE' },
      ConsistentRead: true,
    })
  );

  const dataKeyResponse = await kmsClient.send(
    new GenerateDataKeyCommand({
      KeyId: KMS_KEY_ID,
      KeySpec: 'AES_256',
      EncryptionContext: scopeKmsContext(orgId, scope, vaultId),
    })
  );

  if (!dataKeyResponse.Plaintext || !dataKeyResponse.CiphertextBlob) {
    dataKeyResponse.Plaintext?.fill(0);
    throw new Error('KMS GenerateDataKey did not return usable key material');
  }

  // Take ownership immediately. No DynamoDB call may retain plaintext only in
  // an SDK response object whose lifetime escapes on an exception.
  const plaintextKey = takeAndWipeKmsPlaintext(dataKeyResponse.Plaintext);

  try {
    // Fresh UUID v4 per rotation. Stays with this DEK for life — through ACTIVE
    // state and into ROTATED# state. Phase 7 looks this up via the keyId-index GSI.
    const newKeyId = randomUUID();

    const encryptedDataKey = Buffer.from(dataKeyResponse.CiphertextBlob).toString('base64');

    // RE1: persist the wrapped DEK durably BEFORE any file is re-wrapped under
    // it. commitRotatedScopeDataKey only runs after the whole re-encrypt loop,
    // so a mid-loop crash (15-minute Lambda timeout on a large vault) used to
    // strand every already-re-encrypted head under a keyId with NO stored key
    // material — unreadable except by S3 noncurrent-version rollback. The
    // The immutable KEY# row carries keyId + encryptedDataKey + the KMS EncryptionContext
    // fields (orgId/scope/vaultId) and is discoverable through the keyId-index
    // GSI, so the Phase-7 restore endpoint can re-wrap stranded heads back to
    // the ACTIVE DEK. Prepared rows are never deleted: a crashed or rolled-back
    // rotation can leave an S3 version stamped with the new keyId, making this
    // wrapped key material permanently load-bearing.
    await docClient.send(
      new PutCommand({
        TableName: USER_KEYS_TABLE,
        Item: {
          pk,
          sk: `KEY#${newKeyId}`,
          orgId,
          vaultId,
          scope,
          encryptedDataKey,
          keyId: newKeyId,
          status: 'prepared',
          rotationJobId: jobId,
          createdAt: new Date().toISOString(),
        },
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
      })
    );

    return {
      plaintextKey,
      encryptedDataKey,
      previousItem: currentResult.Item as Record<string, unknown> | undefined,
      newKeyId,
    };
  } catch (error) {
    plaintextKey.fill(0);
    throw error;
  }
}

async function commitRotatedScopeDataKey(
  orgId: string,
  vaultId: string,
  scope: string,
  rotatedBy: string,
  jobId: string,
  prepared: PreparedScopeKey
): Promise<void> {
  const pk = scopeKeyPk(orgId, scope, vaultId);
  const now = new Date().toISOString();

  const previous = prepared.previousItem;
  const previousKeyId = typeof previous?.keyId === 'string' && previous.keyId
    ? previous.keyId
    : 'legacy';
  const previousEncryptedDataKey = typeof previous?.encryptedDataKey === 'string'
    ? previous.encryptedDataKey
    : null;
  const oldKeyRecordSk = previousKeyId === 'legacy'
    ? `KEY#legacy#${Date.now()}`
    : `KEY#${previousKeyId}`;

  const activeCondition = previous
    ? {
        ConditionExpression:
          previousKeyId === 'legacy'
            ? '#status = :active AND encryptedDataKey = :previousEncryptedDataKey AND attribute_not_exists(#keyId)'
            : '#status = :active AND encryptedDataKey = :previousEncryptedDataKey AND #keyId = :previousKeyId',
        ExpressionAttributeNames: { '#status': 'status', '#keyId': 'keyId' },
        ExpressionAttributeValues: {
          ':active': 'active',
          ':previousEncryptedDataKey': previousEncryptedDataKey,
          ...(previousKeyId === 'legacy' ? {} : { ':previousKeyId': previousKeyId }),
        },
      }
    : {
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
      };

  const transactions: NonNullable<ConstructorParameters<typeof TransactWriteCommand>[0]['TransactItems']> = [
    {
      ConditionCheck: {
        TableName: USER_KEYS_TABLE,
        Key: { pk, sk: ROTATION_CONTROL_SK },
        ConditionExpression: '#rotationOwner = :jobId AND #rotationExpiresAt >= :nowEpoch',
        ExpressionAttributeNames: {
          '#rotationOwner': 'rotationOwner',
          '#rotationExpiresAt': 'rotationExpiresAt',
        },
        ExpressionAttributeValues: { ':jobId': jobId, ':nowEpoch': Date.now() },
      },
    },
  ];

  if (previous) {
    transactions.push({
      Put: {
        TableName: USER_KEYS_TABLE,
        Item: {
          ...previous,
          sk: oldKeyRecordSk,
          status: 'rotated',
          rotatedAt: now,
          rotatedBy,
        },
      },
    });
  }

  transactions.push(
    {
      Put: {
        TableName: USER_KEYS_TABLE,
        Item: {
          pk,
          sk: 'ACTIVE',
          orgId,
          vaultId,
          scope,
          encryptedDataKey: prepared.encryptedDataKey,
          keyId: prepared.newKeyId,
          status: 'active',
          createdAt: now,
          lastUsedAt: now,
          rotatedBy,
          rotationJobId: jobId,
        },
        ...activeCondition,
      },
    },
    {
      Put: {
        TableName: USER_KEYS_TABLE,
        Item: {
          pk,
          sk: `KEY#${prepared.newKeyId}`,
          orgId,
          vaultId,
          scope,
          encryptedDataKey: prepared.encryptedDataKey,
          keyId: prepared.newKeyId,
          status: 'active-key-record',
          createdAt: now,
          activatedAt: now,
          rotatedBy,
          rotationJobId: jobId,
        },
        ConditionExpression: '#keyId = :newKeyId AND encryptedDataKey = :newEncryptedDataKey',
        ExpressionAttributeNames: { '#keyId': 'keyId' },
        ExpressionAttributeValues: {
          ':newKeyId': prepared.newKeyId,
          ':newEncryptedDataKey': prepared.encryptedDataKey,
        },
      },
    },
  );

  await docClient.send(
    new TransactWriteCommand({
      ClientRequestToken: createHash('sha256')
        .update(`${jobId}\u0000${vaultId}\u0000${scope}`)
        .digest('hex')
        .slice(0, 36),
      TransactItems: transactions,
    }),
  );
}

async function listAffectedS3Objects(
  orgId: string,
  vaultId: string,
  affectedPaths: string[]
): Promise<string[]> {
  const prefix = vaultS3Prefix(orgId, vaultId);
  const allKeys: string[] = [];
  let continuationToken: string | undefined;

  do {
    const response = await s3Client.send(
      new ListObjectsV2Command({
        Bucket: S3_BUCKET,
        Prefix: prefix,
        ContinuationToken: continuationToken,
        MaxKeys: 1000,
      })
    );

    for (const obj of response.Contents || []) {
      if (!obj.Key) continue;
      const vaultPath = '/' + obj.Key.replace(prefix, '');
      for (const pattern of affectedPaths) {
        if (pathMatchesPattern(vaultPath, pattern)) {
          allKeys.push(obj.Key);
          break;
        }
      }
    }

    continuationToken = response.NextContinuationToken;
  } while (continuationToken);

  return allKeys;
}

// ─── Job Status ─────────────────────────────────────────────────────────────

async function updateJobStatus(
  jobId: string,
  status: ReEncryptionJob['status'],
  updates: Partial<ReEncryptionJob>
): Promise<void> {
  const updateParts: string[] = ['#s = :status'];
  const names: Record<string, string> = { '#s': 'status' };
  const values: Record<string, unknown> = { ':status': status };

  for (const [key, value] of Object.entries(updates)) {
    if (key === 'status') continue;
    const attrKey = `#${key}`;
    const valKey = `:${key}`;
    updateParts.push(`${attrKey} = ${valKey}`);
    names[attrKey] = key;
    values[valKey] = value;
  }

  await docClient.send(
    new UpdateCommand({
      TableName: REENCRYPTION_JOBS_TABLE,
      Key: { jobId },
      UpdateExpression: `SET ${updateParts.join(', ')}`,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
    })
  );
}
