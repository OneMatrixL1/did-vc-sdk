# NationalIDRegistry — Mainnet Release Runbook

Production-grade deploy flow. The deployer key stays inside Frame (encrypted at rest) and never appears in shell history, env files, or CI logs. Two signer options:

- **Frame Hot Signer** (used for the 2026-04-22 mainnet deploy) — private key imported into Frame, encrypted with Frame's password. Fastest path; no phone required.
- **Frame over WalletConnect → MetaMask mobile** — keeps the key on the phone. Slower (every tx needs a manual tap) but no key material on the laptop.

## Mainnet addresses (deployed 2026-04-22)

| Contract | Address | Deploy tx |
|---|---|---|
| `ZKTranscriptLib` | `0x95d8561ab047c0c23367b83A19f14f832d35c29F` | `0xd3706dd9…428a` |
| `UniversalHonkVerifier` | `0x92786a42017f90d60ee8EC66782f34656EDcB043` | `0x0cb3f13b…36aa` |
| `NationalIDRegistry` impl | `0x9fb569fbc1b5aab6fedfa0c9b7b49eae02a6f7c0` | `0x5067b9e4…3cf9` |
| `NationalIDRegistry` proxy | `0x7f1df6a149b5971a4b22ee7a9106fc8889e9c090` | `0x25904815…8660` |

## 0. Prerequisites

- **Frame desktop app** installed. Download DMG from https://frame.sh (no Homebrew cask available).
- **Deployer account in Frame** — either Hot Signer (import private key, encrypt with password) or WalletConnect to a mobile wallet.
- **VNIDChain mainnet** added to Frame:
  - RPC: `https://vnidchain-rpc.vbsn.vn`
  - Chain ID: `54000` (hex `0xd2f0`)
- **Deployer account funded** with VNX native token (testnet deploys cost ~6.5M gas for the verifier pair, ~few million for the registry proxy). At 0.001 gwei base fee on VNIDChain, total spend is negligible — 1 VNX is plenty.
- **Foundry** installed (`curl -L https://foundry.paradigm.xyz | bash && foundryup`) — required for the verifier deploy, which is a Foundry project in `../../did-circuits/contracts/`.
- **Boss's multisig address** (Gnosis Safe or equivalent deployed on VNIDChain mainnet).

## 1. Connect Frame

### 1a. Hot Signer (used for 2026-04-22 deploy)

1. Launch Frame. Menu-bar icon appears.
2. Frame → *Accounts* → *Add Account* → **Hot Signer** → **Import Private Key**.
3. Paste the deployer key, set a Frame password.
4. Frame now stores the key encrypted; it's decrypted in-memory when Frame is unlocked.

### 1b. WalletConnect (alternative, phone-based)

1. Frame → *Accounts* → *Add Account* → **WalletConnect**.
2. MetaMask mobile → *Scan QR code* → approve connection.
3. Keep the phone unlocked during the deploy — every tx needs a tap.

### After either path

4. In Frame's *Chains* panel, ensure **VNIDChain** is present; if not, add it with the RPC + chain ID above.
5. In Frame's main window, **select the deployer account** so it's highlighted.
6. Frame assigns chains *per-dApp*. The first time a new RPC client connects (forge, hardhat, etc.), Frame defaults it to Ethereum mainnet. **Verify the chain** after running any `cast` or `hardhat` command:

   ```bash
   cast chain-id --rpc-url http://127.0.0.1:1248
   # must print: 54000
   ```

   If it prints `1`, open Frame → DAPPS → click the newly-registered dApp → switch its chain to VNIDChain. Re-check with `cast chain-id`.

## ⚠️ Known issue: `forge create --unlocked` silently drops tx data

During the 2026-04-22 deploy, `forge create --unlocked --from 0x… --broadcast` signed and mined successfully (status=1) but the resulting contract had empty bytecode (gas used ~53k, tx `input` field was `0x`). Something in Frame's Hot-signer path or forge's `eth_sendTransaction` serialization strips the init code.

**Workaround (verified to work)**: use `cast send --create <bytecode>` with pre-linked bytecode. Step 2a below follows this pattern.

## 2. Regenerate VKs (only if circuits changed since last deploy)

Skip if the circuit artifacts under `did-circuits/circuits/` haven't changed since your last testnet deploy.

```bash
cd packages/did-vc-sdk/packages/contracts
node scripts/extract-vks-keccak-zk.mjs       # writes events-backend/.../registry/vks.ts
../../node_modules/.bin/ts-node scripts/generate-vks-sol.ts   # writes NationalIDRegistryVKs.sol
npm run compile
```

Verify `VKs` hashes in `contracts/NationalIDRegistryVKs.sol` match what `vks.ts` prints.

## 2a. Deploy UniversalHonkVerifier (only if not already on this chain)

Already deployed on VNIDChain mainnet — see table at top of this doc. Skip this section unless redeploying.

The verifier is a Foundry project. It needs two contracts: `ZKTranscriptLib` (library) and `UniversalHonkVerifier` (links to the library). Use `cast send --create` (NOT `forge create --unlocked` — see known issue above).

```bash
cd did-circuits/contracts
forge build

# Confirm Frame is on chain 54000
cast chain-id --rpc-url http://127.0.0.1:1248   # → 54000

DEPLOYER=0x83DbF49C9F43e918a86d68061c21c9afD20FbD15   # your Frame account
RPC=http://127.0.0.1:1248
GAS_PRICE=1000000   # 0.001 gwei — VNIDChain base fee

# Step A: deploy the library
LIB_BYTECODE=$(python3 -c "import json;print(json.load(open('out/UniversalHonkVerifier.sol/ZKTranscriptLib.json'))['bytecode']['object'])")
cast send --rpc-url $RPC --unlocked --from $DEPLOYER --legacy --gas-price $GAS_PRICE --create $LIB_BYTECODE
# note the contractAddress → $LIB_ADDR
# expected gas: 1,160,939

# Step B: deploy the verifier, linking the library
LIB_ADDR=0x...   # from step A
VERIFIER_BYTECODE=$(forge inspect --libraries "src/UniversalHonkVerifier.sol:ZKTranscriptLib:$LIB_ADDR" UniversalHonkVerifier bytecode)
# sanity: should have no __$…$__ placeholders
echo "$VERIFIER_BYTECODE" | grep -c '__\$' && echo "ERROR: placeholders remain"

cast send --rpc-url $RPC --unlocked --from $DEPLOYER --legacy --gas-price $GAS_PRICE --create $VERIFIER_BYTECODE
# expected gas: 5,318,722
# verifier runtime: 48,702 hex chars (24.35 KB, 226B under EIP-170)
```

Verify the deploys took (non-empty runtime):

```bash
cast code --rpc-url https://vnidchain-rpc.vbsn.vn $LIB_ADDR | wc -c        # > 10000
cast code --rpc-url https://vnidchain-rpc.vbsn.vn $VERIFIER_ADDR | wc -c   # > 48000
```

Zero or very small numbers mean the tx went through but the bytecode was stripped — stop and investigate before proceeding.

## 3. Deploy the registry

Hardhat's deploy path (`npm run deploy:mainnet`) fails with Frame Hot Signer because Frame requires explicit per-dApp account permission — `eth_accounts` returns `[]` for Hardhat's origin even after Frame "knows" the dApp. The 2026-04-22 deploy used the manual `cast send --create` pattern instead (proven to work via the verifier deploy in step 2a).

```bash
cd packages/did-vc-sdk/packages/contracts
npm run compile   # refresh artifacts if needed

DEPLOYER=0x83DbF49C9F43e918a86d68061c21c9afD20FbD15
VERIFIER=0x92786a42017f90d60ee8EC66782f34656EDcB043
RPC=http://127.0.0.1:1248
GAS_PRICE=1000000   # 0.001 gwei

# Step 3a: deploy the NationalIDRegistry implementation
IMPL_BYTECODE=$(python3 -c "import json;print(json.load(open('artifacts/contracts/NationalIDRegistry.sol/NationalIDRegistry.json'))['bytecode'])")
cast send --rpc-url $RPC --unlocked --from $DEPLOYER --legacy --gas-price $GAS_PRICE --create $IMPL_BYTECODE
# note contractAddress → $IMPL_ADDR
# expected gas: ~4M

# Step 3b: deploy ERC1967Proxy pointing to impl, with initialize() calldata
IMPL_ADDR=0x...   # from step 3a
INIT_CALLDATA=$(cast calldata "initialize(address,address)" $VERIFIER $DEPLOYER)
PROXY_BYTECODE=$(python3 -c "import json;print(json.load(open('../../node_modules/@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts-v5/proxy/ERC1967/ERC1967Proxy.sol/ERC1967Proxy.json'))['bytecode'])")
CTOR_ARGS=$(cast abi-encode "constructor(address,bytes)" $IMPL_ADDR $INIT_CALLDATA)
DEPLOY_DATA="${PROXY_BYTECODE}${CTOR_ARGS:2}"

cast send --rpc-url $RPC --unlocked --from $DEPLOYER --legacy --gas-price $GAS_PRICE --create $DEPLOY_DATA
# contractAddress → $PROXY_ADDR — this is your mainnet registry
# expected gas: ~200k
```

Update the mainnet addresses table at the top of this doc with the impl + proxy addresses.

## 4. Smoke-test

With the deployer still selected in Frame (you're still the owner):

```bash
npx hardhat console --network vnidchainMainnet
```

```js
const r = await ethers.getContractAt("NationalIDRegistry", "0xPROXY");
await r.version();            // "1.0.0"
await r.owner();              // your deployer address
await r.verifier();           // VERIFIER_ADDRESS you passed
await r.didDelegateVkHash();  // matches vks.ts
```

If all four match what you expect, the proxy is live and configured correctly.

## 5. Wire the backend relayer

In `events-backend/apps/api/src/modules/registry/registry.service.ts` set the mainnet entry:

```ts
mainnet: {
  rpcUrl: 'https://vnidchain-rpc.vbsn.vn',
  nationalIdRegistry: '0xPROXY',
},
```

Ship a backend release with this change. Client-side, `VITE_NETWORK=mainnet` toggles the submission target.

## 6. Transfer ownership to the multisig

Once smoke-tests pass and the backend is wired, hand the keys over:

```bash
export PROXY_ADDRESS=0xPROXY
export NEW_OWNER=0xSAFE     # the boss's Gnosis Safe
npm run transfer-ownership:mainnet
```

Again, verify on your phone:
- `To: 0xPROXY` (the registry, not the verifier or anything else)
- `Data:` begins with `0xf2fde38b` (selector for `transferOwnership(address)`)
- Next 32 bytes of data equal NEW_OWNER, zero-padded on the left

After confirmation, `r.owner()` returns the Safe address. Your deployer key is no longer privileged — upgrades now require a Safe transaction.

## 7. Retire the deployer key

- Move any remaining mainnet gas back to a treasury wallet.
- Remove the WalletConnect session from Frame (*Accounts* → disconnect).
- Optionally rotate the MetaMask mobile account if it was short-lived for this deploy.

## Rollback / emergencies

UUPS proxies can be upgraded, so "rollback" really means deploying a fixed implementation and calling `upgradeToAndCall(...)` from the owner. After step 6, this is a Safe transaction — assemble it in the Safe UI:

- `To:` proxy
- `Data:` ABI-encoded `upgradeToAndCall(address newImpl, bytes)` — OZ Safe Tx Builder or the `upgrades.upgradeProxy` in a dry run can produce the calldata.
- Require Safe-configured threshold of signers.

**Renouncing ownership** (`renounceOwnership()`) permanently disables upgrades. Do not call this unless the protocol is truly frozen — even then, consider a governance contract instead.

## Escape hatch: deploy without Frame

If Frame is unavailable and you have no choice but to sign with a raw key (e.g. a migration in CI), set:

```bash
export USE_MAINNET_KEY=1
export WALLET_PRIVATE_KEY=0x...
npm run deploy:mainnet -- --network vnidchainMainnetKey
```

Prefer not to use this path. Rotate the key immediately afterwards if you do.
