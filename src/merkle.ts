/**
 * Merkle tree for batch evidence integrity.
 *
 * Uses SHA-256 with a domain-separated leaf / internal-node prefix
 * to prevent second-preimage attacks across levels.
 */

import { createHash } from 'node:crypto';
import { jcsCanonicalize } from './jcs';
import type { EvidenceItem, MerkleInclusionProof } from './types';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

/**
 * Hash a single evidence item into a leaf node.
 */
function hashLeaf(item: EvidenceItem): Buffer {
  const canonical = jcsCanonicalize(item);
  return createHash('sha256')
    .update(LEAF_PREFIX)
    .update(canonical, 'utf-8')
    .digest();
}

/**
 * Hash two child nodes into a parent node.
 */
function hashNode(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256')
    .update(NODE_PREFIX)
    .update(left)
    .update(right)
    .digest();
}

/** A built Merkle tree. */
export interface MerkleTree {
  /** All layers from leaves (index 0) to root (last index). */
  layers: Buffer[][];
  /** Hex-encoded root hash. */
  root: string;
}

/**
 * Build a Merkle tree from an array of evidence items.
 * If the number of leaves at any level is odd, the last node is duplicated.
 */
export function buildMerkleTree(evidence: EvidenceItem[]): MerkleTree {
  if (evidence.length === 0) {
    const emptyRoot = createHash('sha256').update(NODE_PREFIX).digest().toString('hex');
    return { layers: [[Buffer.from(emptyRoot, 'hex')]], root: emptyRoot };
  }

  const leaves = evidence.map(hashLeaf);
  const layers: Buffer[][] = [leaves];

  let current = leaves;
  while (current.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(hashNode(left, right));
    }
    layers.push(next);
    current = next;
  }

  return { layers, root: current[0].toString('hex') };
}

/**
 * Generate an inclusion proof for the evidence item at `leafIndex`.
 */
export function generateInclusionProof(tree: MerkleTree, leafIndex: number): MerkleInclusionProof {
  if (leafIndex < 0 || leafIndex >= tree.layers[0].length) {
    throw new RangeError(`leafIndex ${leafIndex} out of range [0, ${tree.layers[0].length})`);
  }

  const siblings: string[] = [];
  let idx = leafIndex;

  for (let level = 0; level < tree.layers.length - 1; level++) {
    const layer = tree.layers[level];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : idx + 1;
    // If the sibling doesn't exist (odd-length layer, last element), use self.
    const sibling = siblingIdx < layer.length ? layer[siblingIdx] : layer[idx];
    siblings.push(sibling.toString('hex'));
    idx = Math.floor(idx / 2);
  }

  return { leafIndex, siblings };
}

/**
 * Verify a Merkle inclusion proof against a known root.
 */
export function verifyInclusionProof(
  evidenceItem: EvidenceItem,
  proof: MerkleInclusionProof,
  merkleRoot: string,
): boolean {
  let current = hashLeaf(evidenceItem);
  let idx = proof.leafIndex;

  for (const siblingHex of proof.siblings) {
    const sibling = Buffer.from(siblingHex, 'hex');
    const isRight = idx % 2 === 1;
    current = isRight ? hashNode(sibling, current) : hashNode(current, sibling);
    idx = Math.floor(idx / 2);
  }

  return current.toString('hex') === merkleRoot;
}
