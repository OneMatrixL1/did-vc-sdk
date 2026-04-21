// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IUniversalHonkVerifier, Honk} from "./interfaces/IUniversalHonkVerifier.sol";
import {NationalIDRegistryVKs} from "./NationalIDRegistryVKs.sol";

/**
 * @title  NationalIDRegistry
 * @notice On-chain registry for CCCD identity proofs.
 *
 *         Verifies a 5-proof ZK chain, stores identity→DID bindings per
 *         DSC/domain, and emits CA-path events for off-chain DSC whitelist
 *         building.
 *
 * @dev    Proof chain binding:
 *           - sod-validate proves DSC signed the SOD → outputs eContentBinding, dscPubKeyHash
 *           - dg-bridge(13)  links SOD to DG13      → outputs dgBinding(DG13)
 *           - unique-identity extracts identity from DG13 → outputs dgBinding(DG13), identity
 *           - dg-bridge(15)  links SOD to DG15      → outputs dgBinding(DG15) = dg15Binding
 *           - did-delegate   proves chip in DG15 signed Poseidon2(did) → outputs dgBinding(DG15)
 *           The contract enforces:
 *             dgBinding(DG13)  shared between dg-bridge(13) and unique-identity
 *             dg15Binding      shared between dg-bridge(15) and did-delegate
 *           so did ← chip ← DG15 ← SOD and identity ← DG13 ← SOD are both
 *           chained back to the same DSC-signed SOD.
 */
contract NationalIDRegistry is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    NationalIDRegistryVKs
{
    // =========================================================================
    // Errors
    // =========================================================================

    error AlreadyRegistered(bytes32 dscPubKeyHash, bytes32 domain, bytes32 identity);
    error InvalidProof(string circuit);
    error ZeroDID();

    // =========================================================================
    // Events
    // =========================================================================

    /// @notice Emitted on each successful registration.
    event IdentityRegistered(
        bytes32 indexed dscPubKeyHash,
        bytes32 indexed domain,
        bytes32 indexed identity,
        address did
    );

    /// @notice Emitted on every successful registration, carrying a
    ///         caller-supplied CA certificate path for this DSC.
    /// @dev    Not verified on-chain. Off-chain indexers match `dscPubKeyHash`
    ///         against an authoritative DSC list (ICAO PKD or local CSCA
    ///         masterlist) to decide trust. Emitting per-registration — rather
    ///         than once per DSC — removes the first-submitter attack where a
    ///         junk `caPath` would permanently shadow the legitimate one.
    event DSCAnnounced(
        bytes32 indexed dscPubKeyHash,
        bytes caPath
    );

    // =========================================================================
    // Storage  (⚠ APPEND-ONLY — never reorder or delete slots across upgrades)
    // =========================================================================

    /// @notice Verifier contract. Stored (not immutable) so implementations
    ///         can be reused across networks via initializer.
    IUniversalHonkVerifier public verifier;

    /// @notice nid[dscPubKeyHash][domain][identity] → DID (pId address).
    mapping(bytes32 => mapping(bytes32 => mapping(bytes32 => address))) public nid;

    /// @notice count[dscPubKeyHash][domain] → number of registered identities.
    mapping(bytes32 => mapping(bytes32 => uint256)) public count;

    /// @dev Reserved storage for future variables without breaking layout.
    ///      Decrement this when adding a new state variable above.
    uint256[46] private __gap;

    // =========================================================================
    // VK hash getters (compile-time constants from NationalIDRegistryVKs)
    // Regenerate NationalIDRegistryVKs.sol with scripts/generate-vks-sol.ts
    // whenever a circuit is rebuilt, then deploy a new impl and call
    // `upgradeToAndCall(newImpl, "")`.
    // =========================================================================

    function sodVkHash() external pure returns (uint256) { return SOD_VK_HASH; }
    function dgBridgeVkHash() external pure returns (uint256) { return DG_BRIDGE_VK_HASH; }
    function uniqueIdVkHash() external pure returns (uint256) { return UNIQUE_ID_VK_HASH; }
    function didDelegateVkHash() external pure returns (uint256) { return DID_DELEGATE_VK_HASH; }

    // =========================================================================
    // Initializer  (called once via proxy; replaces constructor)
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address verifier_, address owner_) external initializer {
        __Ownable_init(owner_);
        verifier = IUniversalHonkVerifier(verifier_);
    }

    /// @notice Owner-only upgrade authorisation (UUPS).
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Implementation version tag (bump when shipping a new impl).
    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    // =========================================================================
    // Registration
    // =========================================================================

    /**
     * @notice Register a CCCD identity with 5 ZK proofs.
     *
     * @dev VKs are embedded in bytecode (see NationalIDRegistryVKs) — callers do
     *      not supply them. Regenerate NationalIDRegistryVKs.sol whenever a
     *      circuit is rebuilt and redeploy.
     *
     *      Holder-binding chain (DG15 → did):
     *        dg-bridge(dgNumber=15) binds DG15 ← SOD, producing `dg15Binding`.
     *        did-delegate proves the chip's RSA key (inside that same DG15)
     *        signed an ISO 9796-2 message embedding Poseidon2(did), with the
     *        same `dg15Binding` as public output. Passing the same value to
     *        both verifier calls forces them to agree on DG15.
     *
     * @param sodProof        UltraHonk proof for sod-validate
     * @param dgBridgeProof   UltraHonk proof for dg-bridge with dgNumber=13
     * @param uniqueIdProof   UltraHonk proof for unique-identity
     * @param dgBridge15Proof UltraHonk proof for dg-bridge with dgNumber=15 (DG15 ← SOD)
     * @param delegateProof   UltraHonk proof for did-delegate (chip-AA ← did)
     * @param domain          BN254 field element: poseidon2(pack(domainName))
     * @param eContentBinding Output of sod-validate, input of both dg-bridge calls
     * @param dscPubKeyHash   Output of sod-validate — identifies the DSC
     * @param dgBinding       Output of dg-bridge(13) AND unique-identity (must match)
     * @param dg15Binding     Output of dg-bridge(15) AND did-delegate (must match)
     * @param identity        Output of unique-identity — unique per person per domain
     * @param did             DID address (pId from ethr-did-registry)
     * @param caPath          CA certificate path (emitted in event, not verified on-chain)
     */
    function register(
        bytes calldata sodProof,
        bytes calldata dgBridgeProof,
        bytes calldata uniqueIdProof,
        bytes calldata dgBridge15Proof,
        bytes calldata delegateProof,
        bytes32 domain,
        bytes32 eContentBinding,
        bytes32 dscPubKeyHash,
        bytes32 dgBinding,
        bytes32 dg15Binding,
        bytes32 identity,
        address did,
        bytes calldata caPath
    ) external {
        if (did == address(0)) revert ZeroDID();
        if (nid[dscPubKeyHash][domain][identity] != address(0)) {
            revert AlreadyRegistered(dscPubKeyHash, domain, identity);
        }

        // --- Verify sod-validate: [domain, eContentBinding, dscPubKeyHash] ---
        //     VK is loaded from bytecode constants; vkHash is also constant.
        //     The verifier binds vkHash into the Fiat-Shamir transcript, so
        //     a wrong VK or wrong hash both fail verification.
        {
            bytes32[] memory sodPub = new bytes32[](3);
            sodPub[0] = domain;
            sodPub[1] = eContentBinding;
            sodPub[2] = dscPubKeyHash;
            if (!verifier.verify(_sodVk(), SOD_VK_HASH, sodProof, sodPub)) {
                revert InvalidProof("sod-validate");
            }
        }

        // --- Verify dg-bridge(13): [domain, eContentBinding, dgNumber=13, dgBinding] ---
        {
            bytes32[] memory dgPub = new bytes32[](4);
            dgPub[0] = domain;
            dgPub[1] = eContentBinding;
            dgPub[2] = bytes32(uint256(13));
            dgPub[3] = dgBinding;
            if (!verifier.verify(_dgBridgeVk(), DG_BRIDGE_VK_HASH, dgBridgeProof, dgPub)) {
                revert InvalidProof("dg-bridge");
            }
        }

        // --- Verify unique-identity: [domain, dgBinding, identity] ---
        {
            bytes32[] memory idPub = new bytes32[](3);
            idPub[0] = domain;
            idPub[1] = dgBinding;
            idPub[2] = identity;
            if (!verifier.verify(_uniqueIdVk(), UNIQUE_ID_VK_HASH, uniqueIdProof, idPub)) {
                revert InvalidProof("unique-identity");
            }
        }

        // --- Verify dg-bridge(15): [domain, eContentBinding, dgNumber=15, dg15Binding] ---
        //     Same verifier / VK as dg-bridge(13) — only dgNumber and output bindings differ.
        {
            bytes32[] memory dg15Pub = new bytes32[](4);
            dg15Pub[0] = domain;
            dg15Pub[1] = eContentBinding;
            dg15Pub[2] = bytes32(uint256(15));
            dg15Pub[3] = dg15Binding;
            if (!verifier.verify(_dgBridgeVk(), DG_BRIDGE_VK_HASH, dgBridge15Proof, dg15Pub)) {
                revert InvalidProof("dg-bridge-15");
            }
        }

        // --- Verify did-delegate: [domain, did, dg15Binding] ---
        //     Circuit public inputs order matches did-delegate-circuit/src/main.nr:
        //     `domain: pub Field`, `did: pub Field`, then `DIDDelegateOutput.dgBinding`.
        //     The did is passed as a 160-bit address zero-padded into bytes32.
        {
            bytes32[] memory delegatePub = new bytes32[](3);
            delegatePub[0] = domain;
            delegatePub[1] = bytes32(uint256(uint160(did)));
            delegatePub[2] = dg15Binding;
            if (!verifier.verify(_didDelegateVk(), DID_DELEGATE_VK_HASH, delegateProof, delegatePub)) {
                revert InvalidProof("did-delegate");
            }
        }

        // --- Store registration ---
        nid[dscPubKeyHash][domain][identity] = did;
        count[dscPubKeyHash][domain]++;

        // Announce CA path on every scan — off-chain indexers discard entries
        // whose embedded cert pubkey doesn't rehash to `dscPubKeyHash`.
        emit DSCAnnounced(dscPubKeyHash, caPath);
        emit IdentityRegistered(dscPubKeyHash, domain, identity, did);
    }

    // =========================================================================
    // View helpers
    // =========================================================================

    function getNID(
        bytes32 dscPubKeyHash,
        bytes32 domain,
        bytes32 identity
    ) external view returns (address) {
        return nid[dscPubKeyHash][domain][identity];
    }

    function getCount(
        bytes32 dscPubKeyHash,
        bytes32 domain
    ) external view returns (uint256) {
        return count[dscPubKeyHash][domain];
    }
}
