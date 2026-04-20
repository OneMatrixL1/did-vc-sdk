import { ethers, upgrades } from "hardhat";

async function main() {
  const PROXY = "0x060b27091830819050CEBD595947900202653a2B";
  const factory = await ethers.getContractFactory("NationalIDRegistry");
  await upgrades.forceImport(PROXY, factory, { kind: "uups" });
  console.log("manifest synced for proxy:", PROXY);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
