// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IUniversalHonkVerifier, Honk} from "./interfaces/IUniversalHonkVerifier.sol";

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
contract NationalIDRegistry {
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

    /// @notice Emitted once per unique DSC. Off-chain indexers verify the
    ///         CA certificate path and build a trusted DSC whitelist.
    event DSCFirstSeen(
        bytes32 indexed dscPubKeyHash,
        bytes caPath
    );

    // =========================================================================
    // Immutable state (set at deployment, no admin)
    // =========================================================================

    IUniversalHonkVerifier public immutable verifier;

    uint256 public immutable sodVkHash;
    uint256 public immutable dgBridgeVkHash;
    uint256 public immutable uniqueIdVkHash;

    // =========================================================================
    // Mutable state
    // =========================================================================

    /// @notice nid[dscPubKeyHash][domain][identity] → DID (pId address).
    mapping(bytes32 => mapping(bytes32 => mapping(bytes32 => address))) public nid;

    /// @notice count[dscPubKeyHash][domain] → number of registered identities.
    mapping(bytes32 => mapping(bytes32 => uint256)) public count;

    /// @notice Whether the DSCFirstSeen event has already been emitted for this DSC.
    mapping(bytes32 => bool) public dscSeen;

    // =========================================================================
    // Constructor
    // =========================================================================

    constructor(
        address verifier_,
        uint256 sodVkHash_,
        uint256 dgBridgeVkHash_,
        uint256 uniqueIdVkHash_
    ) {
        verifier = IUniversalHonkVerifier(verifier_);
        sodVkHash = sodVkHash_;
        dgBridgeVkHash = dgBridgeVkHash_;
        uniqueIdVkHash = uniqueIdVkHash_;
    }

    // =========================================================================
    // Registration
    // =========================================================================

    /**
     * @notice Register a CCCD identity with 3 ZK proofs.
     *
     * @param sodVk         Verification key for sod-validate circuit
     * @param dgBridgeVk    Verification key for dg-bridge circuit
     * @param uniqueIdVk    Verification key for unique-identity circuit
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
        Honk.VerificationKey calldata sodVk,
        Honk.VerificationKey calldata dgBridgeVk,
        Honk.VerificationKey calldata uniqueIdVk,
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
        //     The verifier binds vkHash into the Fiat-Shamir transcript.
        //     Wrong VK with correct hash → proof fails. Wrong hash → wrong challenges → fails.
        //     We pass our stored immutable hash, ensuring only the correct circuit is accepted.
        {
            bytes32[] memory sodPub = new bytes32[](3);
            sodPub[0] = domain;
            sodPub[1] = eContentBinding;
            sodPub[2] = dscPubKeyHash;
            if (!verifier.verify(sodVk, sodVkHash, sodProof, sodPub)) {
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
            if (!verifier.verify(dgBridgeVk, dgBridgeVkHash, dgBridgeProof, dgPub)) {
                revert InvalidProof("dg-bridge");
            }
        }

        // --- Verify unique-identity: [domain, dgBinding, identity] ---
        {
            bytes32[] memory idPub = new bytes32[](3);
            idPub[0] = domain;
            idPub[1] = dgBinding;
            idPub[2] = identity;
            if (!verifier.verify(uniqueIdVk, uniqueIdVkHash, uniqueIdProof, idPub)) {
                revert InvalidProof("unique-identity");
            }
        }

        // --- Store registration ---
        nid[dscPubKeyHash][domain][identity] = did;
        count[dscPubKeyHash][domain]++;

        // --- Emit DSC CA-path event (once per unique DSC) ---
        if (!dscSeen[dscPubKeyHash]) {
            dscSeen[dscPubKeyHash] = true;
            emit DSCFirstSeen(dscPubKeyHash, caPath);
        }

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
