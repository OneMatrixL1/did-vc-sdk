#!/bin/bash
ETHR_PRIVATE_KEY=0xb88b9077de440ba0d0848ce95ccc130498b722955618673bcb1773689e77032a \
ETHR_NETWORK=vietchain \
ETHR_NETWORK_RPC_URL=https://rpc.vietcha.in \
ETHR_REGISTRY_ADDRESS=0xAE15117A19a481D1729C3d2372Dd40E09cE7F3cE \
npx jest tests/ethr-did-changeowner-pubkey.integration.test.js --verbose --runInBand
