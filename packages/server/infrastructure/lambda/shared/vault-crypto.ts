/**
 * Reusable cloud vault cryptography for Lambda handlers.
 *
 * This module is deliberately route-free. File reads/restores, re-encryption,
 * and future workspace services share the same AES envelope, DEK lookup, KMS
 * encryption context, historical-key binding, and buffer ownership rules.
 */

import {
  DecryptCommand,
  KMSClient,
  type DecryptCommandOutput,
} from '@aws-sdk/client-kms';
import { createHash } from 'node:crypto';

import { emitSecurityMetric } from './metrics';
import {
  AuthError,
  docClient,
  GetCommand,
  QueryCommand,
} from './utils';
import {
  aesDecrypt,
  aesEncrypt,
  getActiveScopeDataKey,
  scopeKeyPk,
  scopeKmsContext,
  takeAndWipeKmsPlaintext,
} from './vault-crypto-core';

export {
  aesDecrypt,
  aesEncrypt,
  encodedScope,
  getActiveScopeDataKey,
  scopeKeyPk,
  scopeKmsContext,
  takeAndWipeKmsPlaintext,
} from './vault-crypto-core';

const REGION = process.env.AWS_REGION || 'eu-west-1';
const USER_KEYS_TABLE = process.env.USER_KEYS_TABLE || 'UserKeysTable';

const kmsClient = new KMSClient({ region: REGION });

export interface VaultCryptoContext {
  orgId: string;
  vaultId: string;
  scope?: string;
}

export interface HistoricalDekItem {
  keyId: string;
  orgId: string;
  vaultId: string;
  scope: string;
  encryptedDataKey: string;
}

export interface EncryptedVaultPayload {
  newCiphertext: Buffer;
  plaintextSize: number;
  plaintextSha256: string;
  encryptedSha256: string;
  currentKeyId: string;
}

function requireCryptoContext(context: VaultCryptoContext): Required<VaultCryptoContext> {
  const scope = context.scope ?? '/**';
  if (!context.orgId || !context.vaultId || !scope) {
    throw new Error('Vault crypto requires orgId, vaultId, and scope');
  }
  return { ...context, scope };
}

function sha256Hex(value: Buffer | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Cheap metadata-only lookup used by upload/write routes. Failures preserve
 * the established behavior: writes proceed without a key-id tag.
 */
export async function getActiveKeyIdForVault(
  orgId: string,
  vaultId: string,
): Promise<string | null> {
  try {
    const result = await docClient.send(
      new GetCommand({
        TableName: USER_KEYS_TABLE,
        Key: { pk: scopeKeyPk(orgId, '/**', vaultId), sk: 'ACTIVE' },
        ConsistentRead: true,
      }),
    );
    const item = result.Item as { keyId?: string; status?: string } | undefined;
    if (item?.status !== 'active') return null;
    return typeof item.keyId === 'string' && item.keyId.length > 0
      ? item.keyId
      : 'legacy';
  } catch (error) {
    console.error('[VaultGuard] getActiveKeyIdForVault failed:', error);
    return null;
  }
}

function vaultBoundHistoricalDekItem(
  item: unknown,
  sourceKeyId: string,
  context: Required<VaultCryptoContext>,
): HistoricalDekItem | null {
  if (!item || typeof item !== 'object') return null;
  const candidate = item as Partial<HistoricalDekItem>;
  if (
    candidate.keyId !== sourceKeyId ||
    candidate.orgId !== context.orgId ||
    candidate.vaultId !== context.vaultId ||
    typeof candidate.scope !== 'string' ||
    candidate.scope.length === 0 ||
    typeof candidate.encryptedDataKey !== 'string' ||
    candidate.encryptedDataKey.length === 0
  ) {
    return null;
  }
  return candidate as HistoricalDekItem;
}

/** Resolve an exact key-id only through an org/vault-bound immutable key row. */
export async function lookupExactDekForVault(
  sourceKeyId: string,
  input: VaultCryptoContext,
): Promise<HistoricalDekItem | null> {
  const context = requireCryptoContext(input);
  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await docClient.send(
      new QueryCommand({
        TableName: USER_KEYS_TABLE,
        IndexName: 'keyId-index',
        KeyConditionExpression: 'keyId = :kid',
        FilterExpression: '#orgId = :orgId AND #vaultId = :vaultId',
        ExpressionAttributeNames: {
          '#orgId': 'orgId',
          '#vaultId': 'vaultId',
        },
        ExpressionAttributeValues: {
          ':kid': sourceKeyId,
          ':orgId': context.orgId,
          ':vaultId': context.vaultId,
        },
        Limit: 25,
      }),
    );
    for (const item of result.Items ?? []) {
      const match = vaultBoundHistoricalDekItem(item, sourceKeyId, context);
      if (match) return match;
    }
    if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return null;
}

/** Compatibility name for callers that treat every non-current key as historical. */
export const lookupHistoricalDekForVault = lookupExactDekForVault;

async function decryptWithExactDataKey(
  ciphertext: Buffer,
  sourceKeyId: string,
  input: VaultCryptoContext,
): Promise<Buffer> {
  const context = requireCryptoContext(input);
  const item = await lookupExactDekForVault(sourceKeyId, context);
  if (!item) {
    throw new AuthError('Historical key material is no longer available', 410);
  }

  let response: DecryptCommandOutput;
  try {
    response = await kmsClient.send(
      new DecryptCommand({
        CiphertextBlob: Buffer.from(item.encryptedDataKey, 'base64'),
        EncryptionContext: scopeKmsContext(context.orgId, item.scope, context.vaultId),
      }),
    );
  } catch (error) {
    await emitSecurityMetric('KMSDecryptFailure');
    throw error;
  }
  if (!response.Plaintext) {
    await emitSecurityMetric('KMSDecryptFailure');
    throw new Error('KMS Decrypt returned no plaintext for historical DEK');
  }

  const historicalKey = takeAndWipeKmsPlaintext(response.Plaintext);
  try {
    return aesDecrypt(ciphertext, historicalKey);
  } finally {
    historicalKey.fill(0);
  }
}

/** Decrypt the current object under the current vault DEK. */
export async function decryptCurrentVaultBlobForRead(
  ciphertext: Buffer,
  input: VaultCryptoContext,
  metadata?: Record<string, string>,
): Promise<{ plaintext: Buffer; keyId: string }> {
  const context = requireCryptoContext(input);
  const recordedKeyId = metadata?.['vaultguard-key-id'];
  if (recordedKeyId && recordedKeyId !== 'legacy') {
    return decryptExactVaultVersion(ciphertext, metadata, context);
  }
  const active = await getActiveScopeDataKey(context.orgId, context.vaultId, context.scope);
  if (!active) {
    throw new AuthError('Vault key unavailable for server-side decrypt.', 409);
  }
  try {
    return { plaintext: aesDecrypt(ciphertext, active.key), keyId: active.keyId };
  } finally {
    active.key.fill(0);
  }
}

/**
 * Decrypt one explicitly selected immutable object version with exactly the
 * key-id recorded on that version. Both ACTIVE and ROTATED key rows are
 * resolved through the tenant-bound key-id index; no unrelated active DEK is
 * unwrapped before the recorded generation has been validated.
 */
export async function decryptExactVaultVersion(
  ciphertext: Buffer,
  metadata: Record<string, string> | undefined,
  input: VaultCryptoContext,
): Promise<{ plaintext: Buffer; keyId: string }> {
  const context = requireCryptoContext(input);
  const sourceKeyId = metadata?.['vaultguard-key-id'];
  if (!sourceKeyId || sourceKeyId === 'legacy') {
    throw new AuthError('Historical key material is no longer available', 410);
  }

  return {
    plaintext: await decryptWithExactDataKey(ciphertext, sourceKeyId, context),
    keyId: sourceKeyId,
  };
}

/**
 * Encrypt caller-owned plaintext under the exact active key generation.
 * Plaintext and active DEK are wiped on every path; the returned ciphertext is
 * owned by the caller and must be wiped after persistence.
 */
export async function encryptPlaintextWithActiveVaultKey(
  plaintext: Buffer,
  input: VaultCryptoContext,
): Promise<EncryptedVaultPayload> {
  const context = requireCryptoContext(input);
  try {
    const plaintextSize = plaintext.byteLength;
    const plaintextSha256 = sha256Hex(plaintext);
    const active = await getActiveScopeDataKey(context.orgId, context.vaultId, context.scope);
    if (!active) throw new Error('No active DEK for vault — cannot encrypt payload');

    try {
      const newCiphertext = aesEncrypt(plaintext, active.key);
      return {
        newCiphertext,
        plaintextSize,
        plaintextSha256,
        encryptedSha256: sha256Hex(newCiphertext),
        currentKeyId: active.keyId,
      };
    } finally {
      active.key.fill(0);
    }
  } finally {
    plaintext.fill(0);
  }
}
