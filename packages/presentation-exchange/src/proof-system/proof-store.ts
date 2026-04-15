/**
 * ProofStore implementations for persisting DomainProofSets.
 */

import type { Domain, DomainProofSet, ProofStore } from './types.js';

// ---------------------------------------------------------------------------
// In-memory store (for testing / short-lived sessions)
// ---------------------------------------------------------------------------

export class MemoryProofStore implements ProofStore {
  private store = new Map<string, DomainProofSet>();
  private index = new Map<string, Domain[]>();

  private key(credentialId: string, domainHash: string): string {
    return `${credentialId}::${domainHash}`;
  }

  async save(proofSet: DomainProofSet): Promise<void> {
    this.store.set(this.key(proofSet.credentialId, proofSet.domain.hash), proofSet);

    const domains = this.index.get(proofSet.credentialId) ?? [];
    if (!domains.some(d => d.hash === proofSet.domain.hash)) {
      domains.push(proofSet.domain);
      this.index.set(proofSet.credentialId, domains);
    }
  }

  async get(credentialId: string, domainHash: string): Promise<DomainProofSet | null> {
    return this.store.get(this.key(credentialId, domainHash)) ?? null;
  }

  async listDomains(credentialId: string): Promise<Domain[]> {
    return this.index.get(credentialId) ?? [];
  }

  async deleteAll(credentialId: string): Promise<void> {
    const domains = this.index.get(credentialId) ?? [];
    for (const d of domains) {
      this.store.delete(this.key(credentialId, d.hash));
    }
    this.index.delete(credentialId);
  }
}

// ---------------------------------------------------------------------------
// localStorage-based store (persistent across sessions)
// ---------------------------------------------------------------------------

/**
 * A ProofStore backed by `localStorage` (or any synchronous key-value store
 * with the same API).
 *
 * Storage layout:
 * - `${prefix}${credentialId}_${domainHash}` → JSON DomainProofSet
 * - `${prefix}index_${credentialId}` → JSON Domain[]
 */
export class LocalStorageProofStore implements ProofStore {
  constructor(
    private readonly prefix: string = 'zkp_proofs_',
    private readonly storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> = globalThis.localStorage,
  ) {}

  private dataKey(credentialId: string, domainHash: string): string {
    return `${this.prefix}${credentialId}_${domainHash}`;
  }

  private indexKey(credentialId: string): string {
    return `${this.prefix}index_${credentialId}`;
  }

  async save(proofSet: DomainProofSet): Promise<void> {
    this.storage.setItem(
      this.dataKey(proofSet.credentialId, proofSet.domain.hash),
      JSON.stringify(proofSet),
    );

    const domains = await this.listDomains(proofSet.credentialId);
    if (!domains.some(d => d.hash === proofSet.domain.hash)) {
      domains.push(proofSet.domain);
      this.storage.setItem(this.indexKey(proofSet.credentialId), JSON.stringify(domains));
    }
  }

  async get(credentialId: string, domainHash: string): Promise<DomainProofSet | null> {
    const json = this.storage.getItem(this.dataKey(credentialId, domainHash));
    return json ? JSON.parse(json) as DomainProofSet : null;
  }

  async listDomains(credentialId: string): Promise<Domain[]> {
    const json = this.storage.getItem(this.indexKey(credentialId));
    return json ? JSON.parse(json) as Domain[] : [];
  }

  async deleteAll(credentialId: string): Promise<void> {
    const domains = await this.listDomains(credentialId);
    for (const d of domains) {
      this.storage.removeItem(this.dataKey(credentialId, d.hash));
    }
    this.storage.removeItem(this.indexKey(credentialId));
  }
}
