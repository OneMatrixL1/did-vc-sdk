// Types
export type {
  LocalizedValue,
  LocalizableString,
  VPRequest,
  UnsignedVPRequest,
  VerifierRequestProof,
  VerifierInfo,
  DocumentRequestNode,
  LogicalRequestNode,
  DocumentRequest,
  DisclosureMode,
  DocumentConditionNode,
  LogicalConditionNode,
  DiscloseCondition,
  MerkleDisclosureRef,
  ZKPCondition,
  ProofSystem,
  KeyDoc,
  VerifiablePresentation,
  SubmissionEntry,
  HolderProof,
  PresentedCredential,
  CredentialProof,
  DataIntegrityProof,
  ZKPProof,
  MerkleDisclosureProof,
  MatchableCredential,
  RuleTreeMatch,
  LogicalRuleMatch,
  DocumentRequestMatch,
  CandidateCredential,
  CredentialSelection,
  SchemaResolver,
  SchemaResolverMap,
  DeriveOptions,
  MerkleWitnessData,
  MerkleFieldData,
  ZKPProvider,
  ZKPProveParams,
  ZKPProveResult,
  ZKPVerifyParams,
  Poseidon2Hasher,
} from './types/index.js';

export { getCredentialIssuerId } from './types/credential.js';

// Builders
export { VPRequestBuilder, DocumentRequestBuilder } from './builder/index.js';

// Resolver
export { matchCredentials, resolvePresentation, evaluateTree, booleanCombine, extractConditions } from './resolver/index.js';

export type { ResolveOptions, UnsignedPresentation, TreeNode, LogicalNode, EvalResult, ExtractedFields } from './resolver/index.js';

// Verifier
export { verifyPresentationStructure, verifyVPRequest, verifyVPRequestFull, verifyVPResponse, verifyZKPProofs, verifyMerkleInclusion } from './verifier/index.js';

export type {
  VerificationResult,
  VerifyRequestOptions,
  VerifyVPRequestResult,
  VerifyVPResponseOptions,
  VerifyVPResponseResult,
  ZKPVerificationResult,
  ZKPProofResult,
} from './verifier/index.js';

// Signer
export { signVPResponse } from './signer/index.js';

// Schema Resolvers
export { jsonSchemaResolver, createICAOSchemaResolver, createBBSResolver, isBBSProof, defaultResolvers } from './resolvers/index.js';

export { createZKPICAOSchemaResolver, isZKPResolver, fieldIdToLeafIndex, fieldIdToTagId, extractSiblingsForLeaf, isDg13Field } from './resolvers/index.js';

export type { ZKPSchemaResolver, ZKPDeriveOptions } from './resolvers/index.js';

// Utils
export { resolveJsonPath } from './utils/jsonpath.js';

export { resolveLocalized } from './utils/localization.js';

export { createKeyDoc } from './utils/keydoc.js';

export type { KeySystem } from './utils/keydoc.js';

export { vpRequestContext } from './utils/vp-request-context.js';
