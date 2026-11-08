/**
 * Core type definitions for the signed receipt system.
 */

/** Verdict outcomes for evidence evaluation. */
export type Verdict = 'PASS' | 'FAIL' | 'CONDITIONAL';

/** A single piece of observed MCP runtime behavior. */
export interface EvidenceItem {
  /** Category of the evidence (e.g. "tool_call", "resource_read", "sampling_request"). */
  type: string;
  /** Free-form payload describing what was observed. */
  payload: Record<string, unknown>;
  /** ISO 8601 timestamp when the behavior was observed. */
  observedAt: string;
}

/** A Merkle inclusion proof for a single evidence item. */
export interface MerkleInclusionProof {
  /** Zero-based index of the leaf in the original evidence array. */
  leafIndex: number;
  /** Sibling hashes from leaf to root. */
  siblings: string[];
}

/** RFC 3161-style trusted timestamp token. */
export interface TimestampToken {
  /** ISO 8601 time asserted by the TSA. */
  timestamp: string;
  /** Identifier / URL of the Timestamp Authority. */
  tsaId: string;
  /** SHA-256 hash of the receipt body that was timestamped. */
  imprint: string;
  /** Nonce used in the request, echoed back. */
  nonce: string;
  /** Simulated TSA signature over the response. */
  tsaSignature: string;
}

/** The complete signed receipt. */
export interface Receipt {
  /** Unique receipt identifier (UUID v4). */
  receiptId: string;
  /** ISO 8601 creation timestamp. */
  timestamp: string;
  /** Identity of the guard / verifier that issued the receipt. */
  issuer: string;
  /** Identity of the MCP server being attested. */
  subject: string;
  /** Ordered array of behavior evidence items. */
  evidence: EvidenceItem[];
  /** SHA-256 hex digest of the JCS-canonicalized evidence array. */
  evidenceHash: string;
  /** Version of the evaluation policy applied. */
  policyVersion: string;
  /** Evaluation outcome. */
  verdict: Verdict;
  /** Merkle root over the evidence array. */
  merkleRoot: string;
  /** Inclusion proofs for each evidence item. */
  inclusionProofs: MerkleInclusionProof[];
  /** Trusted timestamp token. */
  timestampToken: TimestampToken;
  /** Ed25519 signature over the JCS-canonicalized receipt (excluding this field). */
  signature: string;
}

/** Parameters for creating a new receipt. */
export interface CreateReceiptParams {
  issuer: string;
  subject: string;
  evidence: EvidenceItem[];
  policyVersion: string;
  verdict: Verdict;
  signingKey: Buffer;
  /** Optional: override the timestamp (defaults to now). */
  timestamp?: string;
  /** Optional: override the receipt ID (defaults to a new UUID). */
  receiptId?: string;
  /** Optional: TSA configuration for timestamping. */
  tsa?: {
    tsaId: string;
    /** Private key for the simulated TSA. If omitted, an internal key is generated. */
    signingKey?: Buffer;
  };
}

/** Ed25519 key pair. */
export interface KeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}
