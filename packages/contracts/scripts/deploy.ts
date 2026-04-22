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
  // When `accounts: []` is configured (mainnet via Frame), hardhat has no
  // local signer. Ask the RPC (Frame) who it's signing as, then grab the
  // JsonRpcSigner — which routes tx submission back through eth_sendTransaction.
  const signers = await ethers.getSigners();
  let deployer;
  if (signers.length > 0) {
    deployer = signers[0];
  } else {
    const accounts: string[] = await ethers.provider.send("eth_accounts", []);
    if (!accounts || accounts.length === 0) {
      throw new Error(
        "No signer available. Is Frame running at 127.0.0.1:1248 with an account selected?",
      );
    }
    deployer = await ethers.provider.getSigner(accounts[0]);
  }
  console.log("Deploying with:", await deployer.getAddress());
  console.log("Network:        ", network.name, "(chainId", network.config.chainId, ")");
  console.log("Balance:        ", ethers.formatEther(await ethers.provider.getBalance(await deployer.getAddress())));

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
  const factory = await ethers.getContractFactory("NationalIDRegistry", deployer);
  const proxy = await upgrades.deployProxy(
    factory,
    [VERIFIER_ADDRESS, await deployer.getAddress()],  // initialize(verifier_, owner_)
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
  console.log("Owner:                        ", await deployer.getAddress());
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
