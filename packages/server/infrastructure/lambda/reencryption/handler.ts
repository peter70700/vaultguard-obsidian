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
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'crypto';
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

// ─── Types ───────────────────────────────────────────────────────────────────

interface ReEncryptionJob {
  jobId: string;
  orgId: string;
  targetUserId: string;
  triggeredBy: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  totalFiles: number;
  processedFiles: number;
  failedFiles: number;
  errors: string[];
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
  const { targetUserId, orgId, triggeredBy } = event.detail;
  console.info(`[REENCRYPTION] EventBridge trigger: re-encrypt files for revoked user ${targetUserId}`);
  await executeReEncryptionJob(targetUserId, orgId, triggeredBy);
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
  triggeredBy: string
): Promise<string> {
  const jobId = generateId();
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

  try {
    // Step 1: Recover old DEKs from the user's lease records. These cover
    // legacy deployments and tell us which vaults the revoked user actually
    // held usable keys for.
    const oldDeks = await recoverOldDeks(targetUserId, orgId);

    // Step 2: Find affected vaults. The current plugin uses one active key
    // per bound vault, so any revoked access inside a vault rotates that
    // vault's /** key and re-encrypts the vault contents with the new key.
    const affectedScopes = await getAffectedVaultScopes(targetUserId, orgId, oldDeks);

    if (affectedScopes.length === 0) {
      await updateJobStatus(jobId, 'completed', { totalFiles: 0, completedAt: new Date().toISOString() });
      return jobId;
    }

    // Step 3: Rotate each affected vault/scope key and list matching objects.
    const plans = await Promise.all(
      affectedScopes.map(async (affected) => {
        const oldKey = await resolveOldScopeKey(orgId, affected.vaultId, affected.scope, oldDeks);
        const newKey = await prepareRotatedScopeDataKey(orgId, affected.vaultId, affected.scope);
        const s3Keys = await listAffectedS3Objects(orgId, affected.vaultId, [affected.scope]);
        return { ...affected, oldKey, newKey, s3Keys };
      })
    );

    const totalFiles = plans.reduce((sum, plan) => sum + plan.s3Keys.length, 0);

    await updateJobStatus(jobId, 'in_progress', { totalFiles });

    // Step 4: Re-encrypt each file
    let processedFiles = 0;
    let failedFiles = 0;
    const errors: string[] = [];

    for (const plan of plans) {
      const prefix = vaultS3Prefix(orgId, plan.vaultId);
      const processedPlanKeys: string[] = [];
      let planFailed = false;

      for (const s3Key of plan.s3Keys) {
        try {
          const vaultPath = '/' + s3Key.replace(prefix, '');
          await reEncryptFile(
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
          failedFiles++;
          const errMsg = `${s3Key}: ${err instanceof Error ? err.message : String(err)}`;
          errors.push(errMsg);
          console.error(`[REENCRYPTION] Failed: ${errMsg}`);
        }

        if ((processedFiles + failedFiles) % 10 === 0) {
          await updateJobStatus(jobId, 'in_progress', { processedFiles, failedFiles, errors });
        }
      }

      if (planFailed) {
        for (const s3Key of processedPlanKeys) {
          try {
            const vaultPath = '/' + s3Key.replace(prefix, '');
            // Rollback: re-encrypt back to the OLD key, so the object's
            // `vaultguard-key-id` Metadata should reflect the OLD keyId
            // (the DEK the file is now wrapped with after rollback).
            await reEncryptFile(
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
            const errMsg = `${s3Key}: rollback failed: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`;
            errors.push(errMsg);
            console.error(`[REENCRYPTION] ${errMsg}`);
          }
        }
      } else {
        await commitRotatedScopeDataKey(orgId, plan.vaultId, plan.scope, triggeredBy, plan.newKey);
      }
    }

    // Step 5: Wipe recovered and rotated DEKs from memory
    for (const dek of oldDeks) {
      dek.plaintextKey.fill(0);
    }
    for (const plan of plans) {
      plan.oldKey.key.fill(0);
      plan.newKey.plaintextKey.fill(0);
    }

    // Finalize
    const finalStatus = failedFiles === 0 ? 'completed' : (failedFiles === totalFiles ? 'failed' : 'completed');
    const completedAt = new Date().toISOString();
    const ttl = Math.floor(new Date(completedAt).getTime() / 1000) + 90 * 24 * 60 * 60;

    await updateJobStatus(jobId, finalStatus, {
      processedFiles,
      failedFiles,
      errors,
      completedAt,
      expiresAtTtl: ttl,
    });

    await logAudit({
      userId: triggeredBy,
      orgId,
      action: 'reencryption.completed',
      resourcePath: `/re-encryption/${jobId}`,
      outcome: failedFiles === 0 ? 'success' : 'error',
      metadata: { jobId, targetUserId, totalFiles, processedFiles, failedFiles },
    });

    console.info(`[REENCRYPTION] Job ${jobId}: ${processedFiles} re-encrypted, ${failedFiles} failed`);
    return jobId;
  } catch (err) {
    await updateJobStatus(jobId, 'failed', {
      errors: [err instanceof Error ? err.message : String(err)],
      completedAt: new Date().toISOString(),
    });
    throw err;
  }
}

// ─── DEK Recovery ───────────────────────────────────────────────────────────

/**
 * Recovers plaintext DEKs from a revoked user's lease records.
 * Each lease stores an encrypted data key blob; we use KMS Decrypt
 * with the original encryption context to recover the plaintext DEK.
 */
async function recoverOldDeks(userId: string, orgId: string): Promise<RecoveredDek[]> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':uid': userId, ':orgId': orgId },
    })
  );

  const leases = result.Items || [];
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
          plaintextKey: Buffer.from(decryptResponse.Plaintext),
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
            plaintextKey: Buffer.from(decryptResponse.Plaintext),
          });
        }
      } catch (err) {
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
              plaintextKey: Buffer.from(decryptResponse.Plaintext),
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

/**
 * Find the best matching old DEK for a given vault file path.
 * Uses scope specificity: most-specific matching scope wins.
 */
function findDekForPath(vaultPath: string, deks: RecoveredDek[]): RecoveredDek | null {
  let bestMatch: RecoveredDek | null = null;
  let bestSpecificity = -1;

  for (const dek of deks) {
    if (pathMatchesPattern(vaultPath, dek.scope)) {
      const specificity = getScopeSpecificity(dek.scope);
      if (specificity > bestSpecificity) {
        bestMatch = dek;
        bestSpecificity = specificity;
      }
    }
  }

  return bestMatch;
}

function getScopeSpecificity(scope: string): number {
  if (scope === '/**') return 0;
  const segments = scope.split('/').filter(Boolean);
  let score = segments.length * 10;
  for (const seg of segments) {
    if (seg === '**') score -= 8;
    else if (seg === '*') score -= 5;
    else if (seg.includes('*') || seg.includes('?')) score -= 3;
  }
  return score;
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

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted;
}

/**
 * Encrypt plaintext into VaultGuard format with a new random IV.
 * Returns: [IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)]
 */
export function aesEncrypt(plaintext: Buffer, key: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(AES_ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Pack exactly like the plugin Web Crypto path: [IV][ciphertext || tag].
  const result = Buffer.alloc(IV_LENGTH + AUTH_TAG_LENGTH + encrypted.length);
  iv.copy(result, 0);
  encrypted.copy(result, IV_LENGTH);
  authTag.copy(result, IV_LENGTH + encrypted.length);

  return result;
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

  const encryptedPayload = Buffer.from(body);

  // Decrypt with old DEK
  let plaintext: Buffer;
  try {
    plaintext = aesDecrypt(encryptedPayload, oldKey);
  } catch (err) {
    throw new Error(`AES decryption failed for ${vaultPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Re-encrypt with new DEK
  const reEncrypted = aesEncrypt(plaintext, newKey);

  // Zero out sensitive material
  plaintext.fill(0);

  // Upload re-encrypted content
  await s3Client.send(
    new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: s3Key,
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

  const userResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':uid': userId, ':orgId': orgId },
    })
  );

  if (userResult.Items) {
    for (const item of userResult.Items) {
      if (item.pathPattern && item.effect === 'allow') {
        add(item.vaultId, item.pathPattern);
      }
    }
  }

  const wildcardResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':uid': '*', ':orgId': orgId },
    })
  );

  if (wildcardResult.Items) {
    for (const item of wildcardResult.Items) {
      if (item.pathPattern && item.effect === 'allow') {
        add(item.vaultId, item.pathPattern);
      }
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

  return { key: Buffer.from(decryptResponse.Plaintext), keyId };
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
  scope: string
): Promise<PreparedScopeKey> {
  const pk = scopeKeyPk(orgId, scope, vaultId);
  const currentResult = await docClient.send(
    new GetCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk, sk: 'ACTIVE' },
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
    throw new Error('KMS GenerateDataKey did not return usable key material');
  }

  // Fresh UUID v4 per rotation. Stays with this DEK for life — through ACTIVE
  // state and into ROTATED# state. Phase 7 looks this up via the keyId-index GSI.
  const newKeyId = randomUUID();

  const encryptedDataKey = Buffer.from(dataKeyResponse.CiphertextBlob).toString('base64');
  return {
    plaintextKey: Buffer.from(dataKeyResponse.Plaintext),
    encryptedDataKey,
    previousItem: currentResult.Item as Record<string, unknown> | undefined,
    newKeyId,
  };
}

async function commitRotatedScopeDataKey(
  orgId: string,
  vaultId: string,
  scope: string,
  rotatedBy: string,
  prepared: PreparedScopeKey
): Promise<void> {
  const pk = scopeKeyPk(orgId, scope, vaultId);
  const now = new Date().toISOString();

  if (prepared.previousItem) {
    try {
      await docClient.send(
        new PutCommand({
          TableName: USER_KEYS_TABLE,
          Item: {
            // Spread preserves the prior entry's `keyId` (post-backfill) for free —
            // ROTATED# rows carry the OLD keyId; only the new ACTIVE row gets newKeyId.
            ...prepared.previousItem,
            sk: `ROTATED#${now}`,
            status: 'rotated',
            rotatedAt: now,
            rotatedBy,
          },
        })
      );
    } catch (err) {
      // INVARIANT (T-06-01-01): if the prior DEK cannot be preserved as ROTATED#,
      // ABORT the rotation. The new ACTIVE write does NOT run; the existing
      // ACTIVE row remains valid and decryptable. Without this guard, a
      // ROTATED# write failure followed by a successful ACTIVE write would
      // leave noncurrent S3 versions un-decryptable forever.
      throw new Error(
        `Failed to preserve prior DEK as ROTATED#${now}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  await docClient.send(
    new PutCommand({
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
      },
    })
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
