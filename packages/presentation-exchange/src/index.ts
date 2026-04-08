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
  PredicateCondition,
  PredicateOperator,
  PredicateParams,
  ProofSystem,
  KeyDoc,
  VerifiablePresentation,
  SubmissionEntry,
  HolderProof,
  PresentedCredential,
  CredentialProof,
  DataIntegrityProof,
  ICAO9303ZKPProofBundle,
  ZKPProofEntry,
  MatchableCredential,
  RuleTreeMatch,
  LogicalRuleMatch,
  DocumentRequestMatch,
  CandidateCredential,
  CredentialSelection,
  SchemaResolver,
  SchemaResolverMap,
  DeriveOptions,
  SchemaProofSystem,
  ProofSystemMap,
  ProveContext,
  VerifyContext,
  ProofVerificationResult,
  ZKPProvider,
  ZKPProveParams,
  ZKPProveResult,
  ZKPVerifyParams,
  Poseidon2Hasher,
} from './types/index.js';

export { getCredentialIssuerId, isICAOProofBundle, isPredicateCondition } from './types/index.js';

// Builders
export { VPRequestBuilder, DocumentRequestBuilder } from './builder/index.js';

// Resolver
export { matchCredentials, resolvePresentation, evaluateTree, booleanCombine, extractConditions } from './resolver/index.js';

export type { ResolveOptions, UnsignedPresentation, TreeNode, LogicalNode, EvalResult, ExtractedConditions } from './resolver/index.js';

// Verifier
export { verifyPresentationStructure, verifyVPRequest, verifyVPRequestFull, verifyVPResponse } from './verifier/index.js';

export type {
  VerificationResult,
  VerifyRequestOptions,
  VerifyVPRequestResult,
  VerifyVPResponseOptions,
  VerifyVPResponseResult,
} from './verifier/index.js';

// Signer
export { signVPResponse } from './signer/index.js';

// Schema Resolvers
export { createBBSResolver, isBBSProof } from './resolvers/index.js';

// Proof Systems
export { createICAO9303ProofSystem } from './proof-system/index.js';
export type { ICAOCredentialData, ICAO9303ProofSystemOptions } from './proof-system/index.js';

// Utils
export { resolveJsonPath } from './utils/jsonpath.js';
export { resolveLocalized } from './utils/localization.js';
export { createKeyDoc } from './utils/keydoc.js';
export type { KeySystem } from './utils/keydoc.js';
export { vpRequestContext } from './utils/vp-request-context.js';
