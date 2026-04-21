# NationalIDRegistry — Mainnet Release Runbook

Production-grade deploy flow. The deployer key never touches disk — signing goes through Frame over WalletConnect to MetaMask mobile (or a hardware wallet plugged into Frame).

## 0. Prerequisites

- **Frame desktop app** installed. `brew install --cask frame` on macOS, or https://frame.sh for other OSes.
- **MetaMask mobile** on a phone you'll keep unlocked during the deploy, with the deployer account imported.
- **VNIDChain mainnet** added to both Frame and MetaMask mobile:
  - RPC: `https://vnidchain-rpc.vbsn.vn`
  - Chain ID: `54000`
- **Deployer account funded** with VNIDChain mainnet gas (expect ~0.1–1 ETH-equivalent; testnet used ~0.1 for the same contract).
- **UniversalHonkVerifier mainnet address** — confirmed from the chain team (do **not** reuse the testnet verifier `0x81CD798a…B82cc`).
- **Boss's multisig address** (Gnosis Safe or equivalent deployed on VNIDChain mainnet).

## 1. Connect Frame to MetaMask mobile

1. Launch Frame. Menu-bar icon appears.
2. Frame → *Accounts* → *Add Account* → **WalletConnect**.
3. MetaMask mobile → *Scan QR code* → approve connection.
4. In Frame's *Chains* panel, ensure **VNIDChain** is present; if not, add it with the RPC + chain ID above.
5. In Frame's main window, **select the deployer account** so it's highlighted — the next incoming tx will be routed to it.

## 2. Regenerate VKs (only if circuits changed since last deploy)

Skip if the circuit artifacts under `did-circuits/circuits/` haven't changed since your last testnet deploy.

```bash
cd packages/did-vc-sdk/packages/contracts
node scripts/extract-vks-keccak-zk.mjs       # writes events-backend/.../registry/vks.ts
../../node_modules/.bin/ts-node scripts/generate-vks-sol.ts   # writes NationalIDRegistryVKs.sol
npm run compile
```

Verify `VKs` hashes in `contracts/NationalIDRegistryVKs.sol` match what `vks.ts` prints.

## 3. Deploy

```bash
cd packages/did-vc-sdk/packages/contracts

# Required: the real mainnet verifier address — do NOT use the testnet one
export VERIFIER_ADDRESS=0xMAINNET_UNIVERSALHONKVERIFIER

npm run deploy:mainnet
```

What happens:
- Hardhat builds the deploy tx and sends `eth_sendTransaction` to Frame's local proxy (`127.0.0.1:1248`).
- Your phone buzzes; MetaMask mobile shows the tx with `To: (contract creation)`, `Value: 0`, and a long `Data` field.
- **Verify before approving**:
  - `Value` is `0`
  - Network is VNIDChain mainnet (chainId 54000)
  - Gas seems reasonable (a few million for proxy + impl deploy)
- Tap *Confirm*. Frame returns the tx hash to hardhat.
- Hardhat prints the proxy + impl addresses + tx hash when mined.

Copy the printed **Proxy address** — this is your mainnet registry. Save it now.

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
