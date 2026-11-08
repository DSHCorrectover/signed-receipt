/**
 * Ed25519 signature operations using Node.js built-in crypto.
 */

import { createPrivateKey, createPublicKey, sign, verify, generateKeyPairSync, KeyObject } from 'node:crypto';
import { jcsCanonicalize } from './jcs';
import type { KeyPair } from './types';

/**
 * Generate an Ed25519 key pair.
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: exportPublicKeyRaw(publicKey),
    privateKey: exportPrivateKeyRaw(privateKey),
  };
}

/**
 * Sign a value (will be JCS-canonicalized if it is an object).
 * Returns the signature as a hex string.
 */
export function signData(data: unknown, privateKeyRaw: Buffer): string {
  const payload = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(jcsCanonicalize(data), 'utf-8');
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      // Ed25519 PKCS#8 DER prefix (16 bytes) + 32-byte seed
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      privateKeyRaw,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const sig = sign(null, payload, privateKey);
  return sig.toString('hex');
}

/**
 * Verify an Ed25519 signature.
 * @param data - the original data (object or string)
 * @param signatureHex - hex-encoded signature
 * @param publicKeyRaw - 32-byte raw Ed25519 public key
 */
export function verifySignature(data: unknown, signatureHex: string, publicKeyRaw: Buffer): boolean {
  const payload = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(jcsCanonicalize(data), 'utf-8');
  const signature = Buffer.from(signatureHex, 'hex');
  const publicKey = createPublicKey({
    key: Buffer.concat([
      // Ed25519 SPKI DER prefix (12 bytes) + 32-byte raw key
      Buffer.from('302a300506032b6570032100', 'hex'),
      publicKeyRaw,
    ]),
    format: 'der',
    type: 'spki',
  });
  return verify(null, payload, publicKey, signature);
}

// ---- raw key export helpers ----

function exportPublicKeyRaw(keyObj: KeyObject): Buffer {
  const spki = keyObj.export({ format: 'der', type: 'spki' });
  // Last 32 bytes of the SPKI DER encoding are the raw public key.
  return Buffer.from(spki.subarray(spki.length - 32));
}

function exportPrivateKeyRaw(keyObj: KeyObject): Buffer {
  const pkcs8 = keyObj.export({ format: 'der', type: 'pkcs8' });
  // Last 32 bytes of the PKCS#8 DER encoding are the raw seed.
  return Buffer.from(pkcs8.subarray(pkcs8.length - 32));
}
