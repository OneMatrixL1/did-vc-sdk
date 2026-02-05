import AbstractDIDModule from '../abstract/did/module';
import { keypairToAddress } from '../ethr-did/utils';

/**
 * VBSNDIDModule - Module for managing vbsn DIDs (Vietnam Blockchain Social Network)
 * Primarily used for CCCD-based identities.
 */
export default class VBSNDIDModule extends AbstractDIDModule {
    constructor() {
        super(null);
    }

    /**
     * Returns the DID methods supported by this module
     * @returns {Array<string>} Array of supported DID method names
     */
    methods() {
        return ['vbsn'];
    }

    /**
     * Check if this module supports resolving a given DID
     * @param {string} id - DID string or DID URL to check
     * @returns {boolean} True if this module can resolve the DID
     */
    supports(id) {
        return typeof id === 'string' && id.startsWith('did:vbsn:');
    }

    /**
     * Resolve a DID or DID URL
     * @param {string} id - DID string or DID URL (with fragment) to resolve
     * @param {object} [options] - Resolution options
     * @returns {Promise<Object>} DID Document or Verification Method
     */
    async resolve(id, options = {}) {
        const fragmentIndex = id.indexOf('#');
        const baseDid = fragmentIndex !== -1 ? id.substring(0, fragmentIndex) : id;
        const fragment = fragmentIndex !== -1 ? id.substring(fragmentIndex) : null;

        // For did:vbsn, we reconstruct the document based on the DID string
        // This is useful for self-resolving DIDs where the info is encoded in the DID

        // Default document for vbsn DIDs
        const didDocument = {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/v2'
            ],
            id: baseDid,
            verificationMethod: [
                {
                    id: `${baseDid}#controller`,
                    type: 'EcdsaSecp256k1RecoveryMethod2020',
                    controller: baseDid,
                }
            ],
            authentication: [`${baseDid}#controller`],
            assertionMethod: [`${baseDid}#controller`]
        };

        // If a specific verification method is requested
        if (fragment) {
            const vm = didDocument.verificationMethod.find(
                (v) => v.id === id || v.id === fragment || v.id.endsWith(fragment)
            );
            if (vm) {
                return {
                    '@context': didDocument['@context'],
                    ...vm
                };
            }
        }

        return didDocument;
    }

    async getDocument(did) {
        return this.resolve(did);
    }

    async createDocumentTx() {
        throw new Error('Unimplemented');
    }

    async updateDocumentTx() {
        throw new Error('Unimplemented');
    }

    async removeDocumentTx() {
        throw new Error('Unimplemented');
    }
}
