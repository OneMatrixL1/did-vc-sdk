import { expect } from "chai";
import { ethers } from "hardhat";
import { NationalIDRegistry } from "../typechain-types";
import {
  sodValidateVk, sodValidateVkHash,
  dgBridgeVk, dgBridgeVkHash,
  uniqueIdentityVk, uniqueIdentityVkHash,
  sodProof, dgBridgeProof, uniqueIdentityProof,
  domain, eContentBinding, dscPubKeyHash, dgBinding, identity,
} from "./fixtures";

// Deployed UniversalHonkVerifier on VNIDChain testnet (chain 84005)
const VERIFIER_ADDRESS = "0x81CD798a9a2219b9bC7bCfC2019729Bd07eb82cc";

describe("NationalIDRegistry (fork)", function () {
  let registry: NationalIDRegistry;
  const dummyCaPath = "0xdeadbeef";

  before(async function () {
    // Fork VNIDChain testnet to get the real UniversalHonkVerifier
    await ethers.provider.send("hardhat_reset", [{
      forking: { jsonRpcUrl: "https://rpc.vietcha.in" },
    }]);
  });

  after(async function () {
    await ethers.provider.send("hardhat_reset", []);
  });

  beforeEach(async function () {
    const Factory = await ethers.getContractFactory("NationalIDRegistry");
    registry = await Factory.deploy(
      VERIFIER_ADDRESS,
      sodValidateVkHash,
      dgBridgeVkHash,
      uniqueIdentityVkHash,
    );
  });

  describe("Registration with real ZK proofs", function () {
    it("verifies 3 proofs and stores identity", async function () {
      const [signer] = await ethers.getSigners();

      const tx = await registry.register(
        sodValidateVk, dgBridgeVk, uniqueIdentityVk,
        sodProof, dgBridgeProof, uniqueIdentityProof,
        domain, eContentBinding, dscPubKeyHash, dgBinding, identity,
        signer.address,
        dummyCaPath,
      );
      await tx.wait();

      expect(await registry.getNID(dscPubKeyHash, domain, identity)).to.equal(signer.address);
      expect(await registry.getCount(dscPubKeyHash, domain)).to.equal(1);
      expect(await registry.dscSeen(dscPubKeyHash)).to.equal(true);
    });

    it("emits IdentityRegistered and DSCFirstSeen events", async function () {
      const [signer] = await ethers.getSigners();

      await expect(
        registry.register(
          sodValidateVk, dgBridgeVk, uniqueIdentityVk,
          sodProof, dgBridgeProof, uniqueIdentityProof,
          domain, eContentBinding, dscPubKeyHash, dgBinding, identity,
          signer.address,
          dummyCaPath,
        ),
      )
        .to.emit(registry, "IdentityRegistered")
        .withArgs(dscPubKeyHash, domain, identity, signer.address)
        .and.to.emit(registry, "DSCFirstSeen")
        .withArgs(dscPubKeyHash, dummyCaPath);
    });

    it("rejects double registration", async function () {
      const [signer] = await ethers.getSigners();

      await registry.register(
        sodValidateVk, dgBridgeVk, uniqueIdentityVk,
        sodProof, dgBridgeProof, uniqueIdentityProof,
        domain, eContentBinding, dscPubKeyHash, dgBinding, identity,
        signer.address,
        dummyCaPath,
      );

      await expect(
        registry.register(
          sodValidateVk, dgBridgeVk, uniqueIdentityVk,
          sodProof, dgBridgeProof, uniqueIdentityProof,
          domain, eContentBinding, dscPubKeyHash, dgBinding, identity,
          signer.address,
          dummyCaPath,
        ),
      ).to.be.revertedWithCustomError(registry, "AlreadyRegistered");
    });

    it("rejects zero DID", async function () {
      await expect(
        registry.register(
          sodValidateVk, dgBridgeVk, uniqueIdentityVk,
          sodProof, dgBridgeProof, uniqueIdentityProof,
          domain, eContentBinding, dscPubKeyHash, dgBinding, identity,
          ethers.ZeroAddress,
          dummyCaPath,
        ),
      ).to.be.revertedWithCustomError(registry, "ZeroDID");
    });

    it("rejects tampered public inputs", async function () {
      const [signer] = await ethers.getSigners();
      const fakeBinding = ethers.id("tampered");

      await expect(
        registry.register(
          sodValidateVk, dgBridgeVk, uniqueIdentityVk,
          sodProof, dgBridgeProof, uniqueIdentityProof,
          domain, fakeBinding, dscPubKeyHash, dgBinding, identity,
          signer.address,
          dummyCaPath,
        ),
      ).to.be.reverted;
    });

    it("DSCFirstSeen flag set after first registration", async function () {
      const [signer] = await ethers.getSigners();
      expect(await registry.dscSeen(dscPubKeyHash)).to.equal(false);

      await registry.register(
        sodValidateVk, dgBridgeVk, uniqueIdentityVk,
        sodProof, dgBridgeProof, uniqueIdentityProof,
        domain, eContentBinding, dscPubKeyHash, dgBinding, identity,
        signer.address,
        dummyCaPath,
      );

      expect(await registry.dscSeen(dscPubKeyHash)).to.equal(true);
    });
  });

  describe("View helpers", function () {
    it("getNID returns zero for unregistered", async function () {
      expect(await registry.getNID(dscPubKeyHash, domain, identity)).to.equal(ethers.ZeroAddress);
    });

    it("getCount returns 0 for empty", async function () {
      expect(await registry.getCount(dscPubKeyHash, domain)).to.equal(0);
    });
  });

  describe("Immutable state", function () {
    it("stores correct verifier and VK hashes", async function () {
      expect(await registry.verifier()).to.equal(VERIFIER_ADDRESS);
      expect(await registry.sodVkHash()).to.equal(BigInt(sodValidateVkHash));
      expect(await registry.dgBridgeVkHash()).to.equal(BigInt(dgBridgeVkHash));
      expect(await registry.uniqueIdVkHash()).to.equal(BigInt(uniqueIdentityVkHash));
    });
  });
});
