/**
 * JSON-LD context for ZKP proof types used in credential proof arrays.
 *
 * Defines IRIs for all custom properties in ZKPProof, MerkleDisclosure,
 * and DGDisclosure so that JSON-LD expansion/canonicalization works
 * correctly during VP signing and verification.
 *
 * Attach this to a credential's @context when its proof array contains
 * ZKP proof entries.
 */

const VOCAB = 'https://1matrix.app/vocab#';

export const zkpProofContext: Record<string, unknown> = {
  // Proof types
  ZKPProof: `${VOCAB}ZKPProof`,
  MerkleDisclosure: `${VOCAB}MerkleDisclosure`,
  DGDisclosure: `${VOCAB}DGDisclosure`,

  // Shared properties
  conditionID: `${VOCAB}conditionID`,
  fieldId: `${VOCAB}fieldId`,

  // ZKPProof properties
  circuitId: `${VOCAB}circuitId`,
  proofSystem: `${VOCAB}proofSystem`,
  publicInputs: { '@id': `${VOCAB}publicInputs`, '@type': '@json' },
  publicOutputs: { '@id': `${VOCAB}publicOutputs`, '@type': '@json' },
  proofValue: `${VOCAB}proofValue`,

  // MerkleDisclosure properties
  tagId: `${VOCAB}tagId`,
  entropy: `${VOCAB}entropy`,
  siblings: { '@id': `${VOCAB}siblings`, '@container': '@list' },

  // DGDisclosure properties
  dgNumber: `${VOCAB}dgNumber`,
  dgBridgeProof: { '@id': `${VOCAB}dgBridgeProof`, '@type': '@json' },
};
