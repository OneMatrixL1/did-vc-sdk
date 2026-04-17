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
  ZKPCondition,
  ProofSystem,
  KeyDoc,
  VerifierDisclosure,
  VerifiablePresentation,
  SubmissionEntry,
  HolderProof,
  PresentedCredential,
  CredentialProof,
  DataIntegrityProof,
  ZKPProof,
  MatchableCredential,
  MerkleDisclosure,
  DGDisclosure,
  RuleTreeMatch,
  LogicalRuleMatch,
  DocumentRequestMatch,
  CandidateCredential,
  CredentialSelection,
  SchemaResolver,
  SchemaResolverMap,
  DeriveOptions,
  DisclosedField,
  DisclosedDocument,
  DisclosedFieldsResult,
  FieldResult,
  PredicateResult,
  DisclosureMethod,
} from './types/index.js';

export { getCredentialIssuerId } from './types/credential.js';

// Builders
export { VPRequestBuilder } from './builder/index.js';
export { DocumentRequestBuilder } from './builder/index.js';

// Resolver
export { matchCredentials } from './resolver/index.js';
export { resolvePresentation } from './resolver/index.js';
export type { ResolveOptions, UnsignedPresentation } from './resolver/index.js';
export { evaluateTree, booleanCombine } from './resolver/index.js';
export type { TreeNode, LogicalNode, EvalResult } from './resolver/index.js';
export { extractConditions } from './resolver/index.js';
export type { ExtractedFields } from './resolver/index.js';
export { extractDisclosedFields } from './resolver/index.js';

// Verifier
export { verifyPresentationStructure } from './verifier/index.js';
export { verifyVPRequest, verifyVPRequestFull } from './verifier/index.js';
export { verifyVPResponse } from './verifier/index.js';
export type { VerificationResult, VerifyRequestOptions, VerifyVPRequestResult, VerifyVPResponseOptions, VerifyVPResponseResult } from './verifier/index.js';

// Signer
export { signVPResponse } from './signer/index.js';

// Schema Resolvers
export { createICAOSchemaResolver, createBBSResolver, isBBSProof, defaultResolvers } from './resolvers/index.js';

// Utils
export { resolveLocalized } from './utils/localization.js';
export { createKeyDoc } from './utils/keydoc.js';
export type { KeySystem } from './utils/keydoc.js';
export { vpRequestContext } from './utils/vp-request-context.js';
export { zkpProofContext } from './utils/zkp-proof-context.js';

// Proof System
export * from './proof-system/index.js';
