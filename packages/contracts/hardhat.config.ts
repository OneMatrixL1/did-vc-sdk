import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "dotenv/config";

const DEPLOYER_KEY = process.env.WALLET_PRIVATE_KEY;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.27",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    vnidchainTestnet: {
      url: "https://rpc.vietcha.in",
      chainId: 84005,
      accounts: DEPLOYER_KEY ? [DEPLOYER_KEY] : [],
    },
    vnidchainMainnet: {
      url: "https://vnidchain-rpc.vbsn.vn",
      chainId: 54000,
      accounts: DEPLOYER_KEY ? [DEPLOYER_KEY] : [],
    },
  },
};

export default config;
