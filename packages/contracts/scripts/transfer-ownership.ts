import { ethers, network } from "hardhat";

/**
 * Transfer ownership of the NationalIDRegistry proxy to a new owner
 * (typically a Gnosis Safe multisig).
 *
 * Uses the current hardhat network's signer — on `vnidchainMainnet` this goes
 * through Frame, so you'll approve the tx on your phone via MetaMask mobile
 * over WalletConnect. No private key ever on disk.
 *
 * Required env:
 *   PROXY_ADDRESS  — registry proxy (e.g. the address printed by deploy.ts)
 *   NEW_OWNER      — the multisig address that should receive ownership
 *
 * Run:
 *   PROXY_ADDRESS=0x... NEW_OWNER=0x... \
 *     npx hardhat run scripts/transfer-ownership.ts --network vnidchainMainnet
 *
 * After this runs, only NEW_OWNER can authorise upgrades (via UUPS
 * `_authorizeUpgrade`). The old deployer key is no longer privileged —
 * good. Verify afterwards:
 *   npx hardhat console --network vnidchainMainnet
 *   > (await ethers.getContractAt("NationalIDRegistry", "0x...proxy")).owner()
 *
 * Important: OwnableUpgradeable in this contract is one-step — ownership
 * transfers immediately on tx inclusion. Double-check NEW_OWNER before
 * signing, and prefer pasting directly from the Safe UI.
 */
async function main() {
  const PROXY_ADDRESS = process.env.PROXY_ADDRESS;
  const NEW_OWNER = process.env.NEW_OWNER;

  if (!PROXY_ADDRESS || !ethers.isAddress(PROXY_ADDRESS)) {
    throw new Error("Set PROXY_ADDRESS=0x... to the registry proxy");
  }
  if (!NEW_OWNER || !ethers.isAddress(NEW_OWNER)) {
    throw new Error("Set NEW_OWNER=0x... to the multisig address");
  }

  const [signer] = await ethers.getSigners();
  const registry = await ethers.getContractAt("NationalIDRegistry", PROXY_ADDRESS);
  const currentOwner: string = await registry.owner();

  console.log("Network:       ", network.name, `(chainId ${network.config.chainId})`);
  console.log("Proxy:         ", PROXY_ADDRESS);
  console.log("Current owner: ", currentOwner);
  console.log("New owner:     ", NEW_OWNER);
  console.log("Signer:        ", signer.address);

  if (currentOwner.toLowerCase() !== signer.address.toLowerCase()) {
    throw new Error(
      `Signer ${signer.address} is not the current owner ${currentOwner}. Switch to the owning account in Frame.`,
    );
  }
  if (currentOwner.toLowerCase() === NEW_OWNER.toLowerCase()) {
    throw new Error("NEW_OWNER equals current owner — nothing to do");
  }

  console.log("\nSubmitting transferOwnership... (approve on your phone if using Frame)");
  const tx = await registry.transferOwnership(NEW_OWNER);
  console.log("Tx:   ", tx.hash);
  const receipt = await tx.wait(1);
  if (!receipt || receipt.status !== 1) {
    throw new Error(`transferOwnership reverted in tx ${tx.hash}`);
  }

  const finalOwner: string = await registry.owner();
  console.log("\n=== Ownership Transferred ===");
  console.log("Owner is now:", finalOwner);
  if (finalOwner.toLowerCase() !== NEW_OWNER.toLowerCase()) {
    throw new Error("Post-transfer owner does not match NEW_OWNER — investigate");
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
