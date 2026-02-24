import { DIDServiceClient } from '../api-client';
import { didOwnerProofContext } from './constants';

/**
 * Fetch and attach DID owner history to a document (credential or presentation)
 * @param {object} document - The credential or presentation object
 * @param {string} did - The DID to fetch history for
 * @returns {Promise<void>}
 */
export async function attachDIDOwnerProof(document, did) {
    if (!document) return;

    // Determine the correct context property name (support both class-based 'context' and plain '@context')
    const contextKey = document.context !== undefined ? 'context' : '@context';

    // Add context if not present
    if (typeof document.addContext === 'function') {
        // If it's a class instance with addContext method, use it
        const contextList = Array.isArray(document[contextKey]) ? document[contextKey] : [document[contextKey]];
        if (!contextList.some((ctx) => typeof ctx === 'object' && ctx['@context']?.didOwnerProof)) {
            document.addContext(didOwnerProofContext);
        }
    } else {
        // Fallback for plain objects
        if (!Array.isArray(document[contextKey])) {
            document[contextKey] = document[contextKey] ? [document[contextKey]] : [];
        }
        if (!document[contextKey].some((ctx) => typeof ctx === 'object' && ctx['@context']?.didOwnerProof)) {
            document[contextKey].push(didOwnerProofContext);
        }
    }

    // Fetch DID owner history (non-blocking)
    if (did && !document.didOwnerProof) {
        try {
            const didClient = new DIDServiceClient();
            const didOwnerHistory = await didClient.getDIDOwnerHistory(did);
            if (didOwnerHistory && didOwnerHistory.length > 0) {
                document.didOwnerProof = didOwnerHistory;
            }
        } catch (error) {
            // Log warning but don't fail the operation
            console.warn(`Failed to fetch DID owner history: ${error.message}`);
        }
    }
}
