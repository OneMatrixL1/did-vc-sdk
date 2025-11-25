#!/bin/bash
#
# Run ethr DID integration tests on VietChain
#
# Usage: ./scripts/test-integration-vietchain.sh
#

set -e

echo "🧪 Running ethr DID integration tests on VietChain..."
echo ""

# Set VietChain configuration
export ETHR_NETWORK=vietchain
export ETHR_NETWORK_RPC_URL=https://rpc.vietcha.in
export ETHR_REGISTRY_ADDRESS=0xF0889fb2473F91c068178870ae2e1A0408059A03

# Optional: Set private key if provided as argument
if [ -n "$1" ]; then
  export ETHR_PRIVATE_KEY="$1"
  echo "✅ Using provided private key for funded account"
else
  echo "⚠️  No private key provided. Mutation tests will fail."
  echo "   Usage: $0 0x<your-private-key>"
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
