import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { jcsCanonicalize } from '../src/jcs';
import { generateKeyPair, signData, verifySignature } from '../src/signature';
import { buildMerkleTree, generateInclusionProof, verifyInclusionProof } from '../src/merkle';
import { createSimulatedTSA, computeImprint } from '../src/timestamp';
import { createReceipt, verifyReceipt, computeEvidenceHash } from '../src/receipt';
import type { EvidenceItem } from '../src/types';

// ---- JCS ----

describe('JCS (RFC 8785)', () => {
  it('sorts object keys lexicographically', () => {
    const result = jcsCanonicalize({ z: 1, a: 2, m: 3 });
    assert.equal(result, '{"a":2,"m":3,"z":1}');
  });

  it('handles nested objects', () => {
    const result = jcsCanonicalize({ b: { d: 4, c: 3 }, a: 1 });
    assert.equal(result, '{"a":1,"b":{"c":3,"d":4}}');
  });

  it('handles arrays without sorting', () => {
    const result = jcsCanonicalize([3, 1, 2]);
    assert.equal(result, '[3,1,2]');
  });

  it('handles primitives', () => {
    assert.equal(jcsCanonicalize(null), 'null');
    assert.equal(jcsCanonicalize(true), 'true');
    assert.equal(jcsCanonicalize(false), 'false');
    assert.equal(jcsCanonicalize(42), '42');
    assert.equal(jcsCanonicalize('hello'), '"hello"');
  });

  it('produces identical output for equivalent objects with different key order', () => {
    const a = jcsCanonicalize({ x: 1, y: 2 });
    const b = jcsCanonicalize({ y: 2, x: 1 });
    assert.equal(a, b);
  });

  it('throws on NaN', () => {
    assert.throws(() => jcsCanonicalize(NaN), /NaN/);
  });
});

// ---- Ed25519 Signatures ----

describe('Ed25519 signatures', () => {
  it('signs and verifies a string', () => {
    const kp = generateKeyPair();
    const sig = signData('hello world', kp.privateKey);
    assert.equal(verifySignature('hello world', sig, kp.publicKey), true);
  });

  it('signs and verifies an object (JCS-canonicalized)', () => {
    const kp = generateKeyPair();
    const obj = { b: 2, a: 1 };
    const sig = signData(obj, kp.privateKey);
    assert.equal(verifySignature(obj, sig, kp.publicKey), true);
    // Same logical object with different key order should verify
    assert.equal(verifySignature({ a: 1, b: 2 }, sig, kp.publicKey), true);
  });

  it('fails verification with wrong key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const sig = signData('test', kp1.privateKey);
    assert.equal(verifySignature('test', sig, kp2.publicKey), false);
  });

  it('fails verification with tampered data', () => {
    const kp = generateKeyPair();
    const sig = signData('original', kp.privateKey);
    assert.equal(verifySignature('tampered', sig, kp.publicKey), false);
  });

  it('produces 32-byte keys', () => {
    const kp = generateKeyPair();
    assert.equal(kp.publicKey.length, 32);
    assert.equal(kp.privateKey.length, 32);
  });
});

// ---- Merkle Tree ----

describe('Merkle tree', () => {
  const evidence: EvidenceItem[] = [
    { type: 'tool_call', payload: { tool: 'search' }, observedAt: '2026-01-01T00:00:00Z' },
    { type: 'tool_call', payload: { tool: 'read' }, observedAt: '2026-01-01T00:01:00Z' },
    { type: 'resource_read', payload: { uri: 'file:///x' }, observedAt: '2026-01-01T00:02:00Z' },
    { type: 'tool_call', payload: { tool: 'write' }, observedAt: '2026-01-01T00:03:00Z' },
  ];

  it('builds a tree with a deterministic root', () => {
    const t1 = buildMerkleTree(evidence);
    const t2 = buildMerkleTree(evidence);
    assert.equal(t1.root, t2.root);
    assert.equal(t1.root.length, 64); // SHA-256 hex
  });

  it('handles odd number of leaves', () => {
    const odd = evidence.slice(0, 3);
    const tree = buildMerkleTree(odd);
    assert.ok(tree.root.length === 64);
  });

  it('handles single leaf', () => {
    const tree = buildMerkleTree([evidence[0]]);
    assert.ok(tree.root.length === 64);
  });

  it('handles empty evidence', () => {
    const tree = buildMerkleTree([]);
    assert.ok(tree.root.length === 64);
  });

  it('generates and verifies inclusion proofs for all items', () => {
    const tree = buildMerkleTree(evidence);
    for (let i = 0; i < evidence.length; i++) {
      const proof = generateInclusionProof(tree, i);
      assert.equal(proof.leafIndex, i);
      assert.equal(verifyInclusionProof(evidence[i], proof, tree.root), true);
    }
  });

  it('rejects proof for wrong evidence item', () => {
    const tree = buildMerkleTree(evidence);
    const proof = generateInclusionProof(tree, 0);
    // Try to verify item 1 against item 0's proof
    assert.equal(verifyInclusionProof(evidence[1], proof, tree.root), false);
  });

  it('rejects proof against wrong root', () => {
    const tree = buildMerkleTree(evidence);
    const proof = generateInclusionProof(tree, 0);
    assert.equal(verifyInclusionProof(evidence[0], proof, 'aa'.repeat(32)), false);
  });

  it('detects tampered evidence', () => {
    const tree = buildMerkleTree(evidence);
    const proof = generateInclusionProof(tree, 0);
    const tampered = { ...evidence[0], payload: { tool: 'HACKED' } };
    assert.equal(verifyInclusionProof(tampered, proof, tree.root), false);
  });

  it('throws on out-of-range leaf index', () => {
    const tree = buildMerkleTree(evidence);
    assert.throws(() => generateInclusionProof(tree, -1), RangeError);
    assert.throws(() => generateInclusionProof(tree, 999), RangeError);
  });
});

// ---- Timestamp ----

describe('Trusted timestamp', () => {
  it('issues a token with all required fields', () => {
    const tsa = createSimulatedTSA('test-tsa.local');
    const token = tsa.issueToken('abc123');
    assert.ok(token.timestamp);
    assert.equal(token.tsaId, 'test-tsa.local');
    assert.equal(token.imprint, 'abc123');
    assert.ok(token.nonce);
    assert.ok(token.tsaSignature);
  });

  it('computeImprint is deterministic', () => {
    const data = { x: 1, y: 2 };
    assert.equal(computeImprint(data), computeImprint(data));
  });

  it('computeImprint is order-independent', () => {
    const a = computeImprint({ x: 1, y: 2 });
    const b = computeImprint({ y: 2, x: 1 });
    assert.equal(a, b);
  });
});

// ---- Receipt (end-to-end) ----

describe('Receipt generation and verification', () => {
  const sampleEvidence: EvidenceItem[] = [
    { type: 'tool_call', payload: { tool: 'get_forecast', city: 'Beijing' }, observedAt: '2026-11-08T10:00:00Z' },
    { type: 'resource_read', payload: { uri: 'file:///config.json' }, observedAt: '2026-11-08T10:00:01Z' },
    { type: 'sampling_request', payload: { model: 'gpt-4', tokens: 150 }, observedAt: '2026-11-08T10:00:02Z' },
  ];

  it('creates a receipt with all required fields', async () => {
    const kp = generateKeyPair();
    const receipt = await createReceipt({
      issuer: 'guard-v1.example.com',
      subject: 'mcp-server-weather',
      evidence: sampleEvidence,
      policyVersion: '1.0.0',
      verdict: 'PASS',
      signingKey: kp.privateKey,
      timestamp: '2026-11-08T10:00:00Z',
      receiptId: 'test-uuid-001',
    });

    assert.equal(receipt.receiptId, 'test-uuid-001');
    assert.equal(receipt.issuer, 'guard-v1.example.com');
    assert.equal(receipt.subject, 'mcp-server-weather');
    assert.equal(receipt.verdict, 'PASS');
    assert.equal(receipt.policyVersion, '1.0.0');
    assert.ok(receipt.signature);
    assert.ok(receipt.evidenceHash);
    assert.ok(receipt.merkleRoot);
    assert.equal(receipt.evidence.length, 3);
    assert.equal(receipt.inclusionProofs.length, 3);
    assert.ok(receipt.timestampToken);
  });

  it('verifies a valid receipt', async () => {
    const kp = generateKeyPair();
    const receipt = await createReceipt({
      issuer: 'guard-v1',
      subject: 'mcp-server',
      evidence: sampleEvidence,
      policyVersion: '2.0.0',
      verdict: 'CONDITIONAL',
      signingKey: kp.privateKey,
    });

    assert.equal(verifyReceipt(receipt, kp.publicKey), true);
  });

  it('rejects receipt verified with wrong key', async () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const receipt = await createReceipt({
      issuer: 'guard-v1',
      subject: 'mcp-server',
      evidence: sampleEvidence,
      policyVersion: '1.0.0',
      verdict: 'PASS',
      signingKey: kp1.privateKey,
    });

    assert.equal(verifyReceipt(receipt, kp2.publicKey), false);
  });

  it('detects tampered evidence', async () => {
    const kp = generateKeyPair();
    const receipt = await createReceipt({
      issuer: 'guard-v1',
      subject: 'mcp-server',
      evidence: sampleEvidence,
      policyVersion: '1.0.0',
      verdict: 'PASS',
      signingKey: kp.privateKey,
    });

    // Tamper with evidence
    const tampered = { ...receipt, evidence: [...receipt.evidence] };
    tampered.evidence[0] = { ...tampered.evidence[0], payload: { tool: 'HACKED' } };

    assert.equal(verifyReceipt(tampered, kp.publicKey), false);
  });

  it('detects tampered verdict', async () => {
    const kp = generateKeyPair();
    const receipt = await createReceipt({
      issuer: 'guard-v1',
      subject: 'mcp-server',
      evidence: sampleEvidence,
      policyVersion: '1.0.0',
      verdict: 'PASS',
      signingKey: kp.privateKey,
    });

    const tampered = { ...receipt, verdict: 'FAIL' as const };
    assert.equal(verifyReceipt(tampered, kp.publicKey), false);
  });

  it('evidence hash is consistent', () => {
    const h1 = computeEvidenceHash(sampleEvidence);
    const h2 = computeEvidenceHash(sampleEvidence);
    assert.equal(h1, h2);
    assert.equal(h1.length, 64);
  });

  it('works with a single evidence item', async () => {
    const kp = generateKeyPair();
    const receipt = await createReceipt({
      issuer: 'guard-v1',
      subject: 'mcp-server',
      evidence: [sampleEvidence[0]],
      policyVersion: '1.0.0',
      verdict: 'PASS',
      signingKey: kp.privateKey,
    });
    assert.equal(verifyReceipt(receipt, kp.publicKey), true);
  });

  it('works with CONDITIONAL verdict', async () => {
    const kp = generateKeyPair();
    const receipt = await createReceipt({
      issuer: 'guard-v1',
      subject: 'mcp-server',
      evidence: sampleEvidence,
      policyVersion: '1.0.0',
      verdict: 'CONDITIONAL',
      signingKey: kp.privateKey,
    });
    assert.equal(receipt.verdict, 'CONDITIONAL');
    assert.equal(verifyReceipt(receipt, kp.publicKey), true);
  });
});
