import { ethers, upgrades } from "hardhat";

/**
 * Upgrade an existing NationalIDRegistry proxy to a fresh implementation.
 * Run after regenerating NationalIDRegistryVKs.sol for new circuits, or when
 * shipping any logic change.
 *
 * Usage:
 *   PROXY_ADDRESS=0x... hardhat run scripts/upgrade.ts --network vnidchainTestnet
 */
async function main() {
  const proxyAddress = process.env.PROXY_ADDRESS;
  if (!proxyAddress) {
    throw new Error("Set PROXY_ADDRESS env var to the deployed proxy address");
  }

  const [signer] = await ethers.getSigners();
  console.log("Upgrading with:", signer.address);

  const factory = await ethers.getContractFactory("NationalIDRegistry");
  const upgraded = await upgrades.upgradeProxy(proxyAddress, factory, { kind: "uups" });
  await upgraded.waitForDeployment();

  const newImpl = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  console.log("");
  console.log("=== Upgrade Complete ===");
  console.log("Proxy (unchanged):", proxyAddress);
  console.log("New implementation:", newImpl);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
