import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

  // UniversalHonkVerifier already deployed on VNIDChain testnet (chain 84005)
  const VERIFIER_ADDRESS = "0x81CD798a9a2219b9bC7bCfC2019729Bd07eb82cc";

  // VK hashes from did-circuits/contracts/test/fixtures/AllVks.sol
  const SOD_VK_HASH = "0x02784cbb85651ead1623f47f8d625f279e3bfe7b70c2e5cce5b00f72a2f765fd";
  const DG_BRIDGE_VK_HASH = "0x0567502a030452f67c179eee03a5d54f250c6890d106647ed652d9dd7e3025ca";
  const UNIQUE_ID_VK_HASH = "0x2a5d9f27a48ba0efb2f3d27ea36fe59dfa5efae681db6d74e1c82f99827810c2";

  console.log("Deploying NationalIDRegistry...");
  const factory = await ethers.getContractFactory("NationalIDRegistry");
  const registry = await factory.deploy(
    VERIFIER_ADDRESS,
    SOD_VK_HASH,
    DG_BRIDGE_VK_HASH,
    UNIQUE_ID_VK_HASH,
  );

  await registry.waitForDeployment();
  const address = await registry.getAddress();
  const tx = registry.deploymentTransaction();

  console.log("");
  console.log("=== Deployment Complete ===");
  console.log("NationalIDRegistry:", address);
  console.log("Transaction:", tx?.hash);
  console.log("Verifier:", VERIFIER_ADDRESS);
  console.log("Chain: VNIDChain testnet (84005)");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
