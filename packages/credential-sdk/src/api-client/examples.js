/**
 * Example usage of DIDOwnerHistoryClient
 * 
 * This file demonstrates how to use the DID Owner History API client
 * to fetch owner history with signature and message from an external service.
 */

import { DIDServiceClient } from './index';

/**
 * Example 1: Basic usage - Get DID owner history
 */
async function example1_BasicUsage() {
    console.log('\n=== Example 1: Basic Usage ===\n');

    // Initialize the client with your service URL
    const client = new DIDServiceClient();

    try {
        // Get DID owner history
        const result = await client.getDIDOwnerHistory('did:example:123456');

        console.log('✓ Successfully retrieved DID owner history');
        console.log('History records:', result.length);

        return result;
    } catch (error) {
        console.error('✗ Error:', error.message);
        throw error;
    }
}