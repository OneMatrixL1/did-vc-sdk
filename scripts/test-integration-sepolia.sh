#!/bin/bash
#
# Run ethr DID integration tests on Ethereum Sepolia Testnet
#
# Usage: ./scripts/test-integration-sepolia.sh [INFURA_API_KEY] [PRIVATE_KEY]
#

set -e

echo "🧪 Running ethr DID integration tests on Sepolia..."
echo ""

# Set Sepolia configuration
export ETHR_NETWORK=sepolia
export ETHR_REGISTRY_ADDRESS=0x03d5003bf0e79c5f5223588f347eba39afbc3818

# Use Infura API key if provided, otherwise use placeholder
if [ -n "$1" ]; then
  export ETHR_NETWORK_RPC_URL="https://sepolia.infura.io/v3/$1"
  echo "✅ Using provided Infura API key"
else
  export ETHR_NETWORK_RPC_URL="https://sepolia.infura.io/v3/"
  echo "⚠️  No Infura API key provided. Tests may fail."
  echo "   Usage: $0 <infura-api-key> [private-key]"
fi

# Optional: Set private key if provided as second argument
if [ -n "$2" ]; then
  export ETHR_PRIVATE_KEY="$2"
  echo "✅ Using provided private key for funded account"
else
  echo "⚠️  No private key provided. Mutation tests will fail."
fi

echo ""
echo "Configuration:"
echo "  Network: $ETHR_NETWORK"
echo "  RPC URL: $ETHR_NETWORK_RPC_URL"
echo "  Registry: $ETHR_REGISTRY_ADDRESS"
echo ""

# Change to credential-sdk directory and run tests
cd "$(dirname "$0")/../packages/credential-sdk"
yarn test:integration
