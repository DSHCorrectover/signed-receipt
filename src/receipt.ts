/**
 * Receipt generation and verification.
 */

import { createHash, randomUUID } from 'node:crypto';
import { jcsCanonicalize } from './jcs';
import { signData, verifySignature, generateKeyPair } from './signature';
import { buildMerkleTree, generateInclusionProof, verifyInclusionProof } from './merkle';
import { createSimulatedTSA, computeImprint } from './timestamp';
import type { Receipt, CreateReceiptParams, EvidenceItem } from './types';

export { generateKeyPair } from './signature';
export { buildMerkleTree, generateInclusionProof, verifyInclusionProof } from './merkle';
export { createSimulatedTSA, computeImprint } from './timestamp';

/**
 * Compute the SHA-256 hex digest of the JCS-canonicalized evidence array.
 */
export function computeEvidenceHash(evidence: EvidenceItem[]): string {
  const canonical = jcsCanonicalize(evidence);
  return createHash('sha256').update(canonical, 'utf-8').digest('hex');
}

/**
 * Create a fully signed receipt.
 */
export async function createReceipt(params: CreateReceiptParams): Promise<Receipt> {
  const {
    issuer,
    subject,
    evidence,
    policyVersion,
    verdict,
    signingKey,
    timestamp = new Date().toISOString(),
    receiptId = randomUUID(),
  } = params;

  // 1. Evidence hash
  const evidenceHash = computeEvidenceHash(evidence);

  // 2. Merkle tree
  const tree = buildMerkleTree(evidence);
  const inclusionProofs = evidence.map((_, i) => generateInclusionProof(tree, i));

  // 3. Build unsigned receipt body for timestamping
  const receiptBody = { receiptId, timestamp, issuer, subject, evidence, evidenceHash, policyVersion, verdict, merkleRoot: tree.root };
  const imprint = computeImprint(receiptBody);

  // 4. Timestamp token
  const tsa = createSimulatedTSA(
    params.tsa?.tsaId ?? 'simulated-tsa.local',
    params.tsa?.signingKey,
  );
  const timestampToken = tsa.issueToken(imprint);

  // 5. Assemble the receipt (without signature) and sign it
  const unsigned: Omit<Receipt, 'signature'> = {
    receiptId,
    timestamp,
    issuer,
    subject,
    evidence,
    evidenceHash,
    policyVersion,
    verdict,
    merkleRoot: tree.root,
    inclusionProofs,
    timestampToken,
  };

  const signature = signData(unsigned, signingKey);

  return { ...unsigned, signature };
}

/**
 * Verify a receipt's signature, evidence hash, Merkle proofs, and timestamp imprint.
 * Returns true only if every check passes.
 */
export function verifyReceipt(receipt: Receipt, publicKeyRaw: Buffer): boolean {
  // 1. Verify Ed25519 signature over everything except the signature field.
  const { signature: sig, ...unsigned } = receipt;
  if (!verifySignature(unsigned, sig, publicKeyRaw)) {
    return false;
  }

  // 2. Verify evidence hash.
  if (computeEvidenceHash(receipt.evidence) !== receipt.evidenceHash) {
    return false;
  }

  // 3. Verify each Merkle inclusion proof.
  for (let i = 0; i < receipt.evidence.length; i++) {
    if (!verifyInclusionProof(receipt.evidence[i], receipt.inclusionProofs[i], receipt.merkleRoot)) {
      return false;
    }
  }

  // 4. Verify timestamp imprint matches the receipt body.
  const receiptBody = {
    receiptId: receipt.receiptId,
    timestamp: receipt.timestamp,
    issuer: receipt.issuer,
    subject: receipt.subject,
    evidence: receipt.evidence,
    evidenceHash: receipt.evidenceHash,
    policyVersion: receipt.policyVersion,
    verdict: receipt.verdict,
    merkleRoot: receipt.merkleRoot,
  };
  if (computeImprint(receiptBody) !== receipt.timestampToken.imprint) {
    return false;
  }

  return true;
}
