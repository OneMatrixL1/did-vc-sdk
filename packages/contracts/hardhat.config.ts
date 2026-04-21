import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "dotenv/config";

const DEPLOYER_KEY = process.env.WALLET_PRIVATE_KEY;

// Frame's local signing proxy (https://frame.sh). When hardhat sends a tx to
// this URL with no `accounts` configured, it issues `eth_sendTransaction`
// which Frame forwards to the currently selected signer (MetaMask mobile via
// WalletConnect, Ledger, Trezor, etc.). The private key stays on the device.
const FRAME_RPC = process.env.FRAME_RPC || "http://127.0.0.1:1248";

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
    // Testnet: direct private-key signing is fine — deploy key holds only
    // test funds and we redeploy often during development.
    vnidchainTestnet: {
      url: "https://rpc.vietcha.in",
      chainId: 84005,
      accounts: DEPLOYER_KEY ? [DEPLOYER_KEY] : [],
    },
    // Mainnet: sign via Frame so private keys never touch disk. Frame must be
    // running locally with the target account selected (see docs/mainnet-release.md).
    // Hardhat passes the tx to Frame → phone/hardware wallet → signs → broadcasts.
    vnidchainMainnet: {
      url: FRAME_RPC,
      chainId: 54000,
      // `accounts: []` forces hardhat to use eth_sendTransaction via Frame
      // instead of signing locally. Never add DEPLOYER_KEY here.
      accounts: [],
      timeout: 120_000,
    },
    // Escape hatch: mainnet via raw private key, only if you absolutely must
    // run without Frame (e.g. CI migrations). Set USE_MAINNET_KEY=1 to enable.
    ...(process.env.USE_MAINNET_KEY === "1" && DEPLOYER_KEY
      ? {
          vnidchainMainnetKey: {
            url: "https://vnidchain-rpc.vbsn.vn",
            chainId: 54000,
            accounts: [DEPLOYER_KEY],
          },
        }
      : {}),
  },
};

export default config;
