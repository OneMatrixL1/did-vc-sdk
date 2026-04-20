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
 *         Verifies a 3-proof ZK chain (sod-validate → dg-bridge → unique-identity),
 *         stores identity→DID bindings per DSC/domain, and emits CA-path events
 *         for off-chain DSC whitelist building.
 *
 * @dev    Proof chain binding:
 *           - sod-validate proves DSC signed the SOD → outputs eContentBinding, dscPubKeyHash
 *           - dg-bridge   links SOD to DG13 (dgNumber=13) → output dgBinding
 *           - unique-identity extracts identity from DG13  → outputs dgBinding, identity
 *           - dgBinding from dg-bridge MUST equal dgBinding from unique-identity
 *             (enforced by the circuit; the contract passes the same value to both verifier calls)
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
     * @notice Register a CCCD identity with 3 ZK proofs.
     *
     * @dev VKs are embedded in bytecode (see NationalIDRegistryVKs) — callers do
     *      not supply them. Regenerate NationalIDRegistryVKs.sol whenever a
     *      circuit is rebuilt and redeploy.
     *
     * @param sodProof      UltraHonk proof for sod-validate
     * @param dgBridgeProof UltraHonk proof for dg-bridge
     * @param uniqueIdProof UltraHonk proof for unique-identity
     * @param domain        BN254 field element: poseidon2(pack(domainName))
     * @param eContentBinding Output of sod-validate, input of dg-bridge
     * @param dscPubKeyHash Output of sod-validate — identifies the DSC
     * @param dgBinding     Output of dg-bridge AND unique-identity (must match)
     * @param identity      Output of unique-identity — unique per person per domain
     * @param did           DID address (pId from ethr-did-registry)
     * @param caPath        CA certificate path (emitted in event, not verified on-chain)
     */
    function register(
        bytes calldata sodProof,
        bytes calldata dgBridgeProof,
        bytes calldata uniqueIdProof,
        bytes32 domain,
        bytes32 eContentBinding,
        bytes32 dscPubKeyHash,
        bytes32 dgBinding,
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

        // --- Verify dg-bridge: [domain, eContentBinding, dgNumber=13, dgBinding] ---
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
