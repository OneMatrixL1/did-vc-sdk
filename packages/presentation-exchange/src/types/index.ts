export type { LocalizedValue, LocalizableString } from './localization.js';

export type {
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
} from './request.js';

export type {
  VerifiablePresentation,
  SubmissionEntry,
  HolderProof,
  PresentedCredential,
  CredentialProof,
  DataIntegrityProof,
  ZKPProof,
} from './response.js';

export type { MatchableCredential } from './credential.js';
export { getCredentialIssuerId } from './credential.js';

export type {
  RuleTreeMatch,
  LogicalRuleMatch,
  DocumentRequestMatch,
  CandidateCredential,
  CredentialSelection,
} from './matching.js';

export type { SchemaResolver, SchemaResolverMap, DeriveOptions } from './schema-resolver.js';
