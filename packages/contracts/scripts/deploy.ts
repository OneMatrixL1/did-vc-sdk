import { ethers, upgrades, network } from "hardhat";

/**
 * Deploys NationalIDRegistry behind an ERC1967 UUPS proxy.
 *
 * First deployment: creates a fresh proxy + implementation.
 * Subsequent circuit rebuilds: use `scripts/upgrade.ts` — the proxy address
 * stays the same; state (nid / count / dscSeen) is preserved.
 *
 * Verifier address resolution (priority):
 *   1. env VERIFIER_ADDRESS (explicit override, always wins)
 *   2. per-network default embedded below
 * For mainnet, set VERIFIER_ADDRESS to the deployed UniversalHonkVerifier
 * address before running `npm run deploy:mainnet`.
 */
const DEFAULT_VERIFIERS: Record<string, string> = {
  vnidchainTestnet: "0x81CD798a9a2219b9bC7bCfC2019729Bd07eb82cc",
  // mainnet: no default — must be supplied via env to avoid accidentally
  // reusing the testnet verifier at a mainnet proxy.
};

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", deployer.address);
  console.log("Network:        ", network.name, "(chainId", network.config.chainId, ")");
  console.log("Balance:        ", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

  const VERIFIER_ADDRESS =
    process.env.VERIFIER_ADDRESS || DEFAULT_VERIFIERS[network.name] || "";
  if (!VERIFIER_ADDRESS) {
    throw new Error(
      `No UniversalHonkVerifier address for network "${network.name}". ` +
      `Set VERIFIER_ADDRESS=0x... in the environment before deploying.`,
    );
  }
  if (!ethers.isAddress(VERIFIER_ADDRESS)) {
    throw new Error(`Invalid VERIFIER_ADDRESS: ${VERIFIER_ADDRESS}`);
  }

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
  console.log("Network:                      ", network.name, `(chainId ${network.config.chainId})`);
  console.log("");
  console.log("Next: if this was mainnet, transfer ownership to the multisig:");
  console.log(`  PROXY_ADDRESS=${proxyAddress} NEW_OWNER=0x...safe npx hardhat run scripts/transfer-ownership.ts --network ${network.name}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
