/** Low-level cloud AES/KMS helpers shared by the route-free crypto services. */

import {
  DecryptCommand,
  KMSClient,
  type DecryptCommandOutput,
} from '@aws-sdk/client-kms';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import { emitSecurityMetric } from './metrics';
import { docClient, GetCommand } from './utils';

const REGION = process.env.AWS_REGION || 'eu-west-1';
const USER_KEYS_TABLE = process.env.USER_KEYS_TABLE || 'UserKeysTable';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const AES_ALGORITHM = 'aes-256-gcm';
const kmsClient = new KMSClient({ region: REGION });

export function takeAndWipeKmsPlaintext(plaintext: Uint8Array): Buffer {
  const owned = Buffer.from(plaintext);
  plaintext.fill(0);
  return owned;
}

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
    updated.fill(0);
    finalized?.fill(0);
  }
}

export function aesEncrypt(plaintext: Buffer, key: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(AES_ALGORITHM, key, iv);
  const updated = cipher.update(plaintext);
  let finalized: Buffer | null = null;
  let authTag: Buffer | null = null;
  try {
    finalized = cipher.final();
    authTag = cipher.getAuthTag();
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

export function encodedScope(scope: string): string {
  return Buffer.from(scope, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function scopeKeyPk(orgId: string, scope: string, vaultId?: string): string {
  if (!orgId || !scope) throw new Error('Scope key requires orgId and scope');
  const scopePart = encodedScope(scope);
  return vaultId
    ? `ORG#${orgId}#VAULT#${vaultId}#SCOPE#${scopePart}`
    : `ORG#${orgId}#SCOPE#${scopePart}`;
}

export function scopeKmsContext(
  orgId: string,
  scope: string,
  vaultId?: string,
): Record<string, string> {
  return {
    orgId,
    ...(vaultId ? { vaultId } : {}),
    scope,
    purpose: 'vault-scope-dek',
  };
}

export async function getActiveScopeDataKey(
  orgId: string,
  vaultId: string | undefined,
  scope: string,
): Promise<{ key: Buffer; keyId: string } | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk: scopeKeyPk(orgId, scope, vaultId), sk: 'ACTIVE' },
      ConsistentRead: true,
    }),
  );
  const item = result.Item as
    | { encryptedDataKey?: string; status?: string; keyId?: string }
    | undefined;
  if (!item?.encryptedDataKey || item.status !== 'active') return null;

  let response: DecryptCommandOutput;
  try {
    response = await kmsClient.send(
      new DecryptCommand({
        CiphertextBlob: Buffer.from(item.encryptedDataKey, 'base64'),
        EncryptionContext: scopeKmsContext(orgId, scope, vaultId),
      }),
    );
  } catch (error) {
    await emitSecurityMetric('KMSDecryptFailure');
    throw error;
  }
  if (!response.Plaintext) {
    await emitSecurityMetric('KMSDecryptFailure');
    throw new Error(`KMS Decrypt did not return key material for vault ${vaultId || '(legacy)'}`);
  }
  const keyId = typeof item.keyId === 'string' && item.keyId.length > 0
    ? item.keyId
    : 'legacy';
  return { key: takeAndWipeKmsPlaintext(response.Plaintext), keyId };
}
