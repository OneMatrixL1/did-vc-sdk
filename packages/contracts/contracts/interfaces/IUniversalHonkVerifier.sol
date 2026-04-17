// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/**
 * @title Honk proof-system types.
 * @dev   Struct field order MUST match the deployed UniversalHonkVerifier
 *        so that `abi.encode(vk)` produces the same hash.
 */
library Honk {
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct VerificationKey {
        // Misc Params
        uint256 circuitSize;
        uint256 logCircuitSize;
        uint256 publicInputsSize;
        // Selectors  (order matters for abi.encode / VK hash)
        G1Point qm;
        G1Point qc;
        G1Point ql;
        G1Point qr;
        G1Point qo;
        G1Point q4;
        G1Point qLookup;
        G1Point qArith;
        G1Point qDeltaRange;
        G1Point qMemory;
        G1Point qNnf;
        G1Point qElliptic;
        G1Point qPoseidon2External;
        G1Point qPoseidon2Internal;
        // Copy constraints
        G1Point s1;
        G1Point s2;
        G1Point s3;
        G1Point s4;
        // Copy identity
        G1Point id1;
        G1Point id2;
        G1Point id3;
        G1Point id4;
        // Precomputed lookup table
        G1Point t1;
        G1Point t2;
        G1Point t3;
        G1Point t4;
        // Fixed first and last
        G1Point lagrangeFirst;
        G1Point lagrangeLast;
    }
}

/**
 * @title Interface to the deployed UniversalHonkVerifier.
 * @dev   Deployed on VNIDChain testnet at 0x81CD798a9a2219b9bC7bCfC2019729Bd07eb82cc
 */
interface IUniversalHonkVerifier {
    function verify(
        Honk.VerificationKey calldata vk,
        uint256 vkHash,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool verified);
}
