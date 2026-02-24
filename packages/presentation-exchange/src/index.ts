// Types
export type {
  LocalizedValue,
  LocalizableString,
  VPRequest,
  VerifierInfo,
  DocumentRequestNode,
  LogicalRequestNode,
  DocumentRequest,
  DocumentConditionNode,
  LogicalConditionNode,
  DiscloseCondition,
  ZKPCondition,
  ProofSystem,
  VerifiablePresentation,
  SubmissionEntry,
  HolderProof,
  PresentedCredential,
  CredentialProof,
  DataIntegrityProof,
  ZKPProof,
  MatchableCredential,
  RuleTreeMatch,
  LogicalRuleMatch,
  DocumentRequestMatch,
  CandidateCredential,
  CredentialSelection,
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

// Verifier
export { verifyPresentationStructure } from './verifier/index.js';
export type { VerificationResult } from './verifier/index.js';

// Utils
export { resolveJsonPath } from './utils/jsonpath.js';
export { resolveLocalized } from './utils/localization.js';
