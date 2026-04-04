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
  MerkleDisclosureRef,
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
  MerkleDisclosureProof,
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
  MerkleWitnessData,
  MerkleFieldData,
} from './merkle.js';

export type {
  ZKPProvider,
  ZKPProveParams,
  ZKPProveResult,
  ZKPVerifyParams,
  Poseidon2Hasher,
} from './zkp-provider.js';
