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
import { generateDefaultDocument } from '@truvera/credential-sdk/modules/ethr-did';

const doc = generateDefaultDocument('did:ethr:vietchain:0x123...', {
  chainId: 84005,
});
```

**Returns:**
```javascript
{
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
  ],
  id: 'did:ethr:vietchain:0x123...',
  verificationMethod: [{
    id: 'did:ethr:vietchain:0x123...#controller',
    type: 'EcdsaSecp256k1RecoveryMethod2020',
    controller: 'did:ethr:vietchain:0x123...',
    blockchainAccountId: 'eip155:84005:0x123...',
  }],
  authentication: ['did:ethr:vietchain:0x123...#controller'],
  assertionMethod: [
    'did:ethr:vietchain:0x123...#controller',
    'did:ethr:vietchain:0x123...#keys-bbs'
  ],
}
```

### verifyCredentialOptimistic()

Helper function for frontend clients that handles optimistic-first verification with automatic fallback:

```javascript
import {
  EthrDIDModule,
  verifyCredentialOptimistic,
  createLocalStorageAdapter,
} from '@truvera/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });

const result = await verifyCredentialOptimistic(credential, {
  module,
  storage: createLocalStorageAdapter(), // optional
});
```

### verifyPresentationOptimistic()

Helper function for verifying verifiable presentations with optimistic-first resolution. Handles multiple DIDs (presenter + all credential issuers) and uses granular failure detection to mark only the specific DIDs that fail:

```javascript
import {
  EthrDIDModule,
  verifyPresentationOptimistic,
  createMemoryStorageAdapter,
} from '@truvera/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });

const result = await verifyPresentationOptimistic(presentation, {
  module,
  storage: createMemoryStorageAdapter(), // optional
  challenge: 'test-challenge',
  domain: 'example.com', // optional
});
```

**Key Features:**
- Extracts all DIDs from the presentation (holder + all credential issuers)
- Tries optimistic resolution first for all DIDs
- On failure, identifies which specific DID(s) failed (granular detection)
- Only marks the failed DIDs in storage
- Falls back to blockchain resolution

---

## Usage Patterns

### Frontend - Simple (No Storage)

Always tries optimistic first, falls back to blockchain on failure:

```javascript
import { EthrDIDModule, verifyCredentialOptimistic } from '@truvera/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });
const result = await verifyCredentialOptimistic(credential, { module });
```

### Frontend - With localStorage

Remembers which DIDs need blockchain resolution across page refreshes:

```javascript
import {
  EthrDIDModule,
  verifyCredentialOptimistic,
  createLocalStorageAdapter,
} from '@truvera/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });
const storage = createLocalStorageAdapter();

const result = await verifyCredentialOptimistic(credential, { module, storage });
```

### Frontend - With sessionStorage

Clears when tab/window is closed:

```javascript
import {
  verifyCredentialOptimistic,
  createSessionStorageAdapter,
} from '@truvera/credential-sdk/modules/ethr-did';

const storage = createSessionStorageAdapter();
const result = await verifyCredentialOptimistic(credential, { module, storage });
```

### Frontend - With Memory Storage

Clears on page refresh, good for SPAs:

```javascript
import {
  verifyCredentialOptimistic,
  createMemoryStorageAdapter,
} from '@truvera/credential-sdk/modules/ethr-did';

const storage = createMemoryStorageAdapter();
const result = await verifyCredentialOptimistic(credential, { module, storage });

// Clear cache when needed
storage.clear();
```

### Frontend - Verifiable Presentations

Verify presentations with multiple credentials from different issuers:

```javascript
import {
  EthrDIDModule,
  verifyPresentationOptimistic,
  createMemoryStorageAdapter,
} from '@truvera/credential-sdk/modules/ethr-did';

const module = new EthrDIDModule({ networks: [networkConfig] });
const storage = createMemoryStorageAdapter();

const result = await verifyPresentationOptimistic(presentation, {
  module,
  storage,
  challenge: 'unique-challenge-from-verifier',
  domain: 'verifier.example.com',
});

if (result.verified) {
  console.log('Presentation and all credentials verified!');
} else {
  console.log('Verification failed:', result.error);
}
```

### Backend - Manual Control with Redis

Backend has full control over caching strategy:

```javascript
import { EthrDIDModule } from '@truvera/credential-sdk/modules/ethr-did';
import { verifyCredential } from '@truvera/credential-sdk/vc';

const module = new EthrDIDModule({ networks: [networkConfig] });

async function verify(credential, redis) {
  const issuerDID = credential.issuer;
  const isModified = await redis.exists(`modified:${issuerDID}`);

  // Create resolver with optimistic flag based on cache
  const resolver = {
    supports: (id) => module.supports(id),
    resolve: (id) => module.resolve(id, { optimistic: !isModified }),
  };

  let result = await verifyCredential(credential, { resolver });

  if (!result.verified && !isModified) {
    // Mark as modified and retry with blockchain
    await redis.setex(`modified:${issuerDID}`, 3600, '1');
    result = await verifyCredential(credential, { resolver: module });
  }

  return result;
}
```

### Backend - Using verifyCredentialOptimistic with Redis

```javascript
const storage = {
  has: async (did) => !!(await redis.get(`modified:${did}`)),
  set: async (did) => redis.setex(`modified:${did}`, 3600, '1'),
};

const result = await verifyCredentialOptimistic(credential, { module, storage });
```

---

## Storage Adapter Interface

Custom storage adapters must implement:

```typescript
interface StorageAdapter {
  has(did: string): Promise<boolean>;  // Check if DID needs blockchain
  set(did: string): Promise<void>;     // Mark DID as needing blockchain
}
```

**Example: IndexedDB Adapter**

```javascript
const indexedDBStorage = {
  has: async (did) => {
    const db = await openDB();
    return !!(await db.get('modifiedDIDs', did));
  },
  set: async (did) => {
    const db = await openDB();
    await db.put('modifiedDIDs', { did, timestamp: Date.now() });
  },
};
```

---

## Test Coverage

| Test File | Tests | Description |
|-----------|-------|-------------|
| `ethr-did-optimistic.test.js` | 20 | EthrDIDModule optimistic option |
| `ethr-did-verify-optimistic.test.js` | 18 | verifyCredentialOptimistic helper |
| `ethr-did-verify-presentation-optimistic.test.js` | 16 | verifyPresentationOptimistic helper |

### Key Test Cases

1. `generateDefaultDocument()` returns correct structure
2. `getDocument({ optimistic: true })` returns default document (no RPC)
3. `getDocument({ optimistic: false })` fetches from blockchain
4. Constructor `optimistic: true` sets default behavior
5. Per-call option overrides constructor default
6. BBS verification works with optimistic document
7. Storage adapter marks DIDs on verification failure
8. Storage adapter skips optimistic for known modified DIDs
9. VP verification with multiple credentials from different issuers
10. Granular failure detection marks only failed issuer DIDs

---

## Files Changed

| File | Change |
|------|--------|
| `src/modules/ethr-did/module.js` | Added `optimistic` option, `getDefaultDocument()`, refactored `getDocument()` |
| `src/modules/ethr-did/utils.js` | Added `generateDefaultDocument()` |
| `src/modules/ethr-did/verify-optimistic.js` | `verifyCredentialOptimistic()`, `verifyPresentationOptimistic()`, and storage adapters |
| `src/modules/ethr-did/index.js` | Export new functions |
| `tests/ethr-did-optimistic.test.js` | 20 tests for EthrDIDModule optimistic |
| `tests/ethr-did-verify-optimistic.test.js` | 18 tests for verifyCredentialOptimistic |
| `tests/ethr-did-verify-presentation-optimistic.test.js` | 16 tests for verifyPresentationOptimistic |

---

## Performance Considerations

### When Optimistic Helps

- Default DIDs (no on-chain changes): **100% faster** (0 RPC calls)
- First verification of modified DID: **Same** (2 verifications, but 2nd has RPC)
- Subsequent verifications of modified DID with storage: **Same** (1 verification + 1 RPC)

### When to Avoid

- All DIDs are modified on-chain
- Storage overhead is prohibitive
- Verification failure rate is very high

### Recommended Strategy

| Scenario | Recommendation |
|----------|----------------|
| Frontend, most DIDs unmodified | `verifyCredentialOptimistic` with `sessionStorage` |
| Backend, high volume | Manual control with Redis, TTL 1 hour |
| Backend, low volume | `verifyCredentialOptimistic` with memory storage |
