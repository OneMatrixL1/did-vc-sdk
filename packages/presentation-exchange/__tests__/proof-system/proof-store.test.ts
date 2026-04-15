/**
 * Proof store tests — verifies real CRUD behavior for both
 * MemoryProofStore and LocalStorageProofStore.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryProofStore, LocalStorageProofStore } from '../../src/proof-system/proof-store.js';
import type { DomainProofSet, ProofStore } from '../../src/proof-system/types.js';

function makeProofSet(credentialId: string, domainName: string, domainHash: string): DomainProofSet {
  const proof = {
    circuitId: 'test',
    proofValue: 'base64proof_' + domainHash,
    publicInputs: { domain: domainHash },
    publicOutputs: { dgBinding: '0x' + domainHash.slice(2, 10) },
  };
  return {
    domain: { name: domainName, hash: domainHash },
    credentialId,
    createdAt: new Date().toISOString(),
    sodValidate: { ...proof, circuitId: 'sod-validate' },
    dgBridge: { ...proof, circuitId: 'dg-bridge' },
    dg13Merklelize: { ...proof, circuitId: 'dg13-merklelize' },
    merkleTree: {
      root: '0xroot_' + domainHash,
      commitment: '0xcommit_' + domainHash,
      leaves: Array.from({ length: 16 }, (_, i) => '0xleaf' + i),
      siblings: Array.from({ length: 16 }, (_, i) =>
        Array.from({ length: 4 }, (_, j) => '0xsib' + i + '_' + j),
      ),
      leafData: Array.from({ length: 16 }, () => ({
        length: '10',
        data: ['0x0', '0x0', '0x0', '0x0'] as const,
      })),
    },
  };
}

/** Simple in-memory Storage implementation for testing LocalStorageProofStore */
function createStorage(): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> {
  const data = new Map<string, string>();
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => { data.set(key, value); },
    removeItem: (key: string) => { data.delete(key); },
  };
}

describe.each([
  ['MemoryProofStore', () => new MemoryProofStore() as ProofStore],
  ['LocalStorageProofStore', () => new LocalStorageProofStore('test_', createStorage()) as ProofStore],
])('%s', (_name, factory) => {
  let store: ProofStore;

  beforeEach(() => { store = factory(); });

  it('round-trips a proof set through save/get', async () => {
    const ps = makeProofSet('cred_001', '1matrix', '0xaaa111');
    await store.save(ps);

    const loaded = await store.get('cred_001', '0xaaa111');
    expect(loaded).not.toBeNull();
    expect(loaded!.credentialId).toBe('cred_001');
    expect(loaded!.domain.name).toBe('1matrix');
    expect(loaded!.domain.hash).toBe('0xaaa111');
    expect(loaded!.sodValidate.circuitId).toBe('sod-validate');
    expect(loaded!.merkleTree.leaves).toHaveLength(16);
    expect(loaded!.merkleTree.siblings).toHaveLength(16);
    expect(loaded!.merkleTree.siblings[0]).toHaveLength(4);
  });

  it('returns null for nonexistent credential', async () => {
    expect(await store.get('nonexistent', '0xfff')).toBeNull();
  });

  it('returns null for wrong domain hash', async () => {
    await store.save(makeProofSet('cred_001', '1matrix', '0xaaa'));
    expect(await store.get('cred_001', '0xbbb')).toBeNull();
  });

  it('stores multiple domains for one credential independently', async () => {
    await store.save(makeProofSet('cred_001', '1matrix', '0xaaa'));
    await store.save(makeProofSet('cred_001', 'partner', '0xbbb'));

    const a = await store.get('cred_001', '0xaaa');
    const b = await store.get('cred_001', '0xbbb');
    expect(a!.domain.name).toBe('1matrix');
    expect(b!.domain.name).toBe('partner');
    expect(a!.sodValidate.proofValue).not.toBe(b!.sodValidate.proofValue);
  });

  it('lists all domains for a credential', async () => {
    await store.save(makeProofSet('cred_001', '1matrix', '0xaaa'));
    await store.save(makeProofSet('cred_001', 'partner', '0xbbb'));
    await store.save(makeProofSet('cred_002', '1matrix', '0xaaa'));

    const domains = await store.listDomains('cred_001');
    expect(domains).toHaveLength(2);
    expect(domains.map(d => d.hash).sort()).toEqual(['0xaaa', '0xbbb']);
  });

  it('does not duplicate domain on overwrite', async () => {
    await store.save(makeProofSet('cred_001', '1matrix', '0xaaa'));
    await store.save(makeProofSet('cred_001', '1matrix', '0xaaa'));

    expect(await store.listDomains('cred_001')).toHaveLength(1);
  });

  it('deleteAll removes all domains for a credential', async () => {
    await store.save(makeProofSet('cred_001', '1matrix', '0xaaa'));
    await store.save(makeProofSet('cred_001', 'partner', '0xbbb'));
    await store.save(makeProofSet('cred_002', '1matrix', '0xaaa'));

    await store.deleteAll('cred_001');

    expect(await store.get('cred_001', '0xaaa')).toBeNull();
    expect(await store.get('cred_001', '0xbbb')).toBeNull();
    expect(await store.listDomains('cred_001')).toEqual([]);
    // Other credential unaffected
    expect(await store.get('cred_002', '0xaaa')).not.toBeNull();
  });

  it('deleteAll on empty credential is a no-op', async () => {
    await store.deleteAll('nonexistent'); // should not throw
    expect(await store.listDomains('nonexistent')).toEqual([]);
  });
});
