# Signed Receipt

[**Commercial verification engagements — USD 8,000–15,000, court-ready dossier**](https://dshcorrectover.github.io/correctover-recovery-admission/services.html) · [**Independent audit & conformance**](https://dshcorrectover.github.io/correctover-recovery-admission/services.html)

SCITT-style cryptographically signed receipts for MCP runtime behavior evidence.

Implements JCS (RFC 8785) + Ed25519 + Merkle trees.

## Overview

This library produces tamper-evident, verifiable receipts that attest to observed
MCP server runtime behavior. Each receipt binds a set of evidence items to a
timestamp and an Ed25519 signature, with a Merkle tree ensuring individual
evidence items cannot be silently modified.

### Design Goals

- **COSE-compatible**: receipt format aligns with COSE (CBOR Object Signing and Encryption) concepts
- **Verifiable**: anyone with the public key can verify receipt authenticity
- **Tamper-evident**: Merkle tree ensures evidence items can't be modified without detection
- **Time-bound**: trusted timestamps prove when behavior was observed

## Components

| Module | Purpose |
|---|---|
| `types.ts` | All TypeScript interfaces |
| `jcs.ts` | JSON Canonicalization Scheme (RFC 8785) |
| `signature.ts` | Ed25519 key generation, signing, verification |
| `merkle.ts` | Merkle tree construction, inclusion proofs |
| `timestamp.ts` | RFC 3161-style trusted timestamp simulation |
| `receipt.ts` | Receipt generation and verification orchestration |

## Usage

```typescript
import { generateKeyPair, createReceipt, verifyReceipt } from 'signed-receipt';

// Generate a signing key pair
const keyPair = generateKeyPair();

// Create a signed receipt
const receipt = await createReceipt({
  issuer: 'guard-v1.example.com',
  subject: 'mcp-server-weather',
  evidence: [
    { type: 'tool_call', tool: 'get_forecast', result: 'sunny', duration_ms: 42 }
  ],
  policyVersion: '1.0.0',
  verdict: 'PASS',
  signingKey: keyPair.privateKey,
});

// Verify the receipt
const valid = verifyReceipt(receipt, keyPair.publicKey);
```

## Requirements

- Node.js >= 18
- No external crypto dependencies (uses built-in `node:crypto`)

## License

MIT
