import type { MatchableCredential } from './credential.js';
import type { DocumentRequest } from './request.js';

// ---------------------------------------------------------------------------
// Match result tree (mirrors the request tree structure)
// ---------------------------------------------------------------------------

export type RuleTreeMatch = LogicalRuleMatch | DocumentRequestMatch;

export interface LogicalRuleMatch {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: RuleTreeMatch[];
  satisfied: boolean;
}

export interface DocumentRequestMatch {
  type: 'DocumentRequest';
  request: DocumentRequest;
  candidates: CandidateCredential[];
  satisfied: boolean;
}

export interface CandidateCredential {
  credential: MatchableCredential;
  /** Index in the original credentials array */
  index: number;
  /** Which disclose field paths are present */
  disclosedFields: string[];
  /** Which disclose field paths are missing (non-optional) */
  missingFields: string[];
  /** ZKP condition IDs whose private inputs resolve */
  satisfiableZKPs: string[];
  /** ZKP condition IDs whose private inputs are missing */
  unsatisfiableZKPs: string[];
  /** Overall: all required disclose fields present + all ZKP private inputs resolve */
  fullyQualified: boolean;
}

// ---------------------------------------------------------------------------
// User selection (input to resolvePresentation)
// ---------------------------------------------------------------------------

export interface CredentialSelection {
  docRequestID: string;
  credentialIndex: number;
}
