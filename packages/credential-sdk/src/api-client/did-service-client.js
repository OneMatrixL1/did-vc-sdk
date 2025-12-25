import AbstractApiClient from './abstract';

// Default base URL for the API service
const DEFAULT_BASE_URL = 'https://api.example.com';

/**
 * DID Service API Client
 * Provides methods to interact with DID-related API services
 * Can be extended with more API methods as needed
 */
class DIDServiceClient extends AbstractApiClient {
    /**
     * @param {string} [baseUrl] - Base URL of the API service (optional, uses default if not provided)
     * @param {object} [options] - Additional options
     */
    constructor(baseUrl = DEFAULT_BASE_URL, options = {}) {
        super(baseUrl, options);
    }

    /**
     * Get DID owner history with signature and message
     * @param {string} did - The DID identifier
     * @returns {Promise<Array<{signature: string, message: {identity: string, oldOwner: string, newOwner: string}}>>} 
     * Returns array of objects, each containing:
     * - signature: string - The cryptographic signature
     * - message: object with:
     *   - identity: string - Address (uint160) of the identity (DID address)
     *   - oldOwner: string - Address (uint160) of the previous owner
     *   - newOwner: string - Address (uint160) of the new owner
     * Example: [
     *   { 
     *     signature: '0x123...', 
     *     message: { 
     *       identity: '0x742d...', 
     *       oldOwner: '0x0000...',
     *       newOwner: '0xA1B2...' 
     *     }
     *   },
     *   ...
     * ]
     */
    async getDIDOwnerHistory(did) {
        this._validateParams({ did }, ['did']);

        // Parse DID to extract address
        // Expected format: did:ethr:network:address or did:ethr:address
        const parseDIDAddress = (didString) => {
            const parts = didString.split(':');
            // Get the last part which should be the address
            const address = parts[parts.length - 1];

            // Validate it looks like an Ethereum address
            if (!address || !address.match(/^0x[a-fA-F0-9]{40}$/)) {
                throw new Error(`Invalid DID format: unable to extract valid address from ${didString}`);
            }

            return address;
        };

        const identity = parseDIDAddress(did);

        // TODO: Replace with real API call when available
        // Mock data for testing
        // Message structure: { identity: address (DID), oldOwner: address, newOwner: address }
        const mockHistory = [
            {
                signature: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
                message: {
                    identity,
                    oldOwner: '0x0000000000000000000000000000000000000000',
                    newOwner: '0xA1B2C3D4E5F6789012345678901234567890ABCD'
                }
            },
            {
                signature: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
                message: {
                    identity,
                    oldOwner: '0xA1B2C3D4E5F6789012345678901234567890ABCD',
                    newOwner: '0xBCDEF1234567890abcdef1234567890abcdef12'
                }
            },
            {
                signature: '0x567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456',
                message: {
                    identity,
                    oldOwner: '0xBCDEF1234567890abcdef1234567890abcdef12',
                    newOwner: '0x567890abcdef1234567890abcdef1234567890ab'
                }
            }
        ];

        return mockHistory;

        /* Real API implementation (commented out for now):
        try {
            const response = await this.get(`/did/${did}/owner-history`);

            // Validate response is an array
            if (!Array.isArray(response)) {
                throw new Error('Invalid response: expected array of history records');
            }

            // Validate each item has signature and message
            const validatedHistory = response.map((item, index) => {
                if (!item.signature || !item.message) {
                    throw new Error(`Invalid history item at index ${index}: missing signature or message`);
                }

                // Validate message structure
                const { identity, oldOwner, newOwner } = item.message;
                if (!identity || !oldOwner || !newOwner) {
                    throw new Error(`Invalid history item at index ${index}: message must contain identity, oldOwner, and newOwner`);
                }

                return {
                    signature: item.signature,
                    message: {
                        identity,
                        oldOwner,
                        newOwner
                    }
                };
            });

            return validatedHistory;
        } catch (error) {
            throw new Error(`Failed to get DID owner history: ${error.message}`);
        }
        */
    }
}

export default DIDServiceClient;

