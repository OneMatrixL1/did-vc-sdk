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
  PredicateCondition,
  PredicateOperator,
  PredicateParams,
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

export type {
  SchemaProofSystem,
  ProofSystemMap,
  ProveContext,
  VerifyContext,
  ProofVerificationResult,
  DSCVerificationResult,
} from './proof-system.js';

export type {
  ICAO9303ZKPProofBundle as ICAOProofBundle,
  ICAO9303ZKPProofBundle,
  ZKPProofEntry,
  MerkleDisclosure,
} from './icao-proof-bundle.js';
export { isICAOProofBundle } from './icao-proof-bundle.js';
export { isPredicateCondition } from './condition.js';

export type {
  ZKPProvider,
  ZKPProveParams,
  ZKPProveResult,
  ZKPVerifyParams,
  Poseidon2Hasher,
} from './zkp-provider.js';
