# Optimistic DID Resolution for Ethr DIDs

## Overview

Optimistic DID resolution is a performance optimization that generates default DID documents locally without making blockchain RPC calls. This is useful when most DIDs have not been modified on-chain.

### How It Works

1. **Optimistic First**: Generate default DID document locally (no RPC)
2. **Verify**: Attempt credential verification with the default document
3. **Fallback**: If verification fails, fetch from blockchain and retry

### When to Use

- **Most DIDs are unmodified**: If 90%+ of your DIDs have no on-chain changes
- **Performance critical**: When RPC latency is a bottleneck
- **BBS credentials**: Works well with BBS address-based recovery verification

---

## API Reference

### verifyCredentialOptimistic()

Helper function that tries optimistic resolution first, then falls back to blockchain:

```javascript
import {
  EthrDIDModule,
  verifyCredentialOptimistic,
} from '@docknetwork/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });

const result = await verifyCredentialOptimistic(credential, { module });
```

### verifyPresentationOptimistic()

Helper function for verifying verifiable presentations with optimistic-first resolution:

```javascript
import {
  EthrDIDModule,
  verifyPresentationOptimistic,
} from '@docknetwork/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });

const result = await verifyPresentationOptimistic(presentation, {
  module,
  challenge: 'test-challenge',
  domain: 'example.com', // optional
});
```

### EthrDIDModule Options

#### Constructor Option

```javascript
const module = new EthrDIDModule({
  networks: [networkConfig],
  optimistic: true,  // Default to optimistic resolution
});
```

#### Per-Call Option

```javascript
// Force optimistic (no RPC)
await module.getDocument(did, { optimistic: true });

// Force blockchain
await module.getDocument(did, { optimistic: false });

// Use constructor default
await module.getDocument(did);
```

### generateDefaultDocument()

Generate a default DID document without blockchain fetch:

```javascript
import { generateDefaultDocument } from '@docknetwork/credential-sdk/modules/ethr-did';

const doc = generateDefaultDocument('did:ethr:vietchain:0x123...', {
  chainId: 84005,
});
```

---

## Usage Patterns

### Simple Usage

Always tries optimistic first, falls back to blockchain on failure:

```javascript
import { EthrDIDModule, verifyCredentialOptimistic } from '@docknetwork/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });
const result = await verifyCredentialOptimistic(credential, { module });
```

### Verifiable Presentations

Verify presentations with multiple credentials from different issuers:

```javascript
import {
  EthrDIDModule,
  verifyPresentationOptimistic,
} from '@docknetwork/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });

const result = await verifyPresentationOptimistic(presentation, {
  module,
  challenge: 'unique-challenge-from-verifier',
  domain: 'verifier.example.com',
});

if (result.verified) {
  console.log('Presentation and all credentials verified!');
} else {
  console.log('Verification failed:', result.error);
}
```

### Backend - Manual Control

Backend has full control over caching strategy:

```javascript
import { EthrDIDModule } from '@docknetwork/credential-sdk/modules/ethr-did';
import { verifyCredential } from '@docknetwork/credential-sdk/vc';

const module = new EthrDIDModule({ networks: [networkConfig] });

async function verify(credential) {
  // Try optimistic first
  const optimisticResolver = {
    supports: (id) => module.supports(id),
    resolve: (id) => module.resolve(id, { optimistic: true }),
  };

  let result = await verifyCredential(credential, { resolver: optimisticResolver });

  if (!result.verified) {
    // Fallback to blockchain
    result = await verifyCredential(credential, { resolver: module });
  }

  return result;
}

### Fallback: Fallback to blockchain

If verification fails with the default document, the SDK can attempt verification using the `didOwnerProof` (if present) or fall back to a full blockchain resolution.

For more details on how history can be verified off-chain, see [DID Owner Proof](./did-owner-proof.md).

---

## Test Coverage

| Test File | Tests | Description |
|-----------|-------|-------------|
| `ethr-did-optimistic.test.js` | 20 | EthrDIDModule optimistic option |
| `ethr-did-verify-optimistic.test.js` | 5 | verifyCredentialOptimistic helper |
| `ethr-did-verify-presentation-optimistic.test.js` | 10 | verifyPresentationOptimistic helper |

---

## Files Changed

| File | Change |
|------|--------|
| `src/modules/ethr-did/module.js` | Added `optimistic` option, `getDefaultDocument()`, refactored `getDocument()` |
| `src/modules/ethr-did/utils.js` | Added `generateDefaultDocument()` |
| `src/modules/ethr-did/verify-optimistic.js` | `verifyCredentialOptimistic()`, `verifyPresentationOptimistic()` |
| `src/modules/ethr-did/index.js` | Export new functions |

---

## Performance Considerations

### When Optimistic Helps

- Default DIDs (no on-chain changes): **100% faster** (0 RPC calls)
- First verification of modified DID: **Same** (2 verifications, but 2nd has RPC)

### When to Avoid

- All DIDs are modified on-chain
- Verification failure rate is very high

### Recommended Strategy

| Scenario | Recommendation |
|----------|----------------|
| Frontend | `verifyCredentialOptimistic` |
| Backend, high volume | Manual control with caching |
| Backend, low volume | `verifyCredentialOptimistic` |
