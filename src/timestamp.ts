/**
 * Trusted timestamp integration — RFC 3161-style simulation.
 *
 * In production this would contact a real TSA (e.g. 联合信任 TSACert).
 * Here we simulate the request/response flow with a local key pair so the
 * rest of the receipt pipeline can be exercised end-to-end.
 */

import { createHash, randomUUID, generateKeyPairSync, sign, createPrivateKey, KeyObject } from 'node:crypto';
import { jcsCanonicalize } from './jcs';
import type { TimestampToken } from './types';

/** A simulated TSA instance. */
export interface TSA {
  tsaId: string;
  /** Issue a timestamp token for the given data imprint. */
  issueToken(imprint: string): TimestampToken;
}

/**
 * Create a simulated TSA backed by an Ed25519 key.
 */
export function createSimulatedTSA(tsaId: string, signingKey?: Buffer): TSA {
  let privateKeyObj: KeyObject;
  if (signingKey) {
    privateKeyObj = createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        signingKey,
      ]),
      format: 'der',
      type: 'pkcs8',
    });
  } else {
    privateKeyObj = generateKeyPairSync('ed25519').privateKey;
  }

  return {
    tsaId,
    issueToken(imprint: string): TimestampToken {
      const nonce = randomUUID();
      const timestamp = new Date().toISOString();

      // Build the TSTInfo-like structure and sign it.
      const tstInfo = jcsCanonicalize({ imprint, nonce, timestamp, tsaId });
      const tsaSignature = sign(null, Buffer.from(tstInfo, 'utf-8'), privateKeyObj).toString('hex');

      return { timestamp, tsaId, imprint, nonce, tsaSignature };
    },
  };
}

/**
 * Compute the SHA-256 imprint (hex) of a data structure.
 */
export function computeImprint(data: unknown): string {
  const canonical = typeof data === 'string' ? data : jcsCanonicalize(data);
  return createHash('sha256').update(canonical, 'utf-8').digest('hex');
}
