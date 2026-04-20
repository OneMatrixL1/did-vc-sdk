import { ethers, upgrades } from "hardhat";

/**
 * Deploys NationalIDRegistry behind an ERC1967 UUPS proxy.
 *
 * First deployment: creates a fresh proxy + implementation.
 * Subsequent circuit rebuilds: use `scripts/upgrade.ts` — the proxy address
 * stays the same; state (nid / count / dscSeen) is preserved.
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

  // UniversalHonkVerifier already deployed on VNIDChain testnet (chain 84005)
  const VERIFIER_ADDRESS = "0x81CD798a9a2219b9bC7bCfC2019729Bd07eb82cc";

  console.log("Deploying NationalIDRegistry (UUPS proxy)...");
  const factory = await ethers.getContractFactory("NationalIDRegistry");
  const proxy = await upgrades.deployProxy(
    factory,
    [VERIFIER_ADDRESS, deployer.address],  // initialize(verifier_, owner_)
    { kind: "uups" },
  );
  await proxy.waitForDeployment();

  const proxyAddress = await proxy.getAddress();
  const implAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  const tx = proxy.deploymentTransaction();

  console.log("");
  console.log("=== Deployment Complete ===");
  console.log("Proxy (use this address):     ", proxyAddress);
  console.log("Implementation (current impl):", implAddress);
  console.log("Owner:                        ", deployer.address);
  console.log("Verifier:                     ", VERIFIER_ADDRESS);
  console.log("Deploy tx:                    ", tx?.hash);
  console.log("Chain: VNIDChain testnet (84005)");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
