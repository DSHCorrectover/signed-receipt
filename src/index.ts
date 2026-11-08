/**
 * signed-receipt — public API surface.
 */

export type {
  Verdict,
  EvidenceItem,
  MerkleInclusionProof,
  TimestampToken,
  Receipt,
  CreateReceiptParams,
  KeyPair,
} from './types';

export { jcsCanonicalize } from './jcs';
export { generateKeyPair, signData, verifySignature } from './signature';
export { buildMerkleTree, generateInclusionProof, verifyInclusionProof } from './merkle';
export { createSimulatedTSA, computeImprint } from './timestamp';
export { createReceipt, verifyReceipt, computeEvidenceHash } from './receipt';
