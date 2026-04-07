import type { MatchableCredential } from './credential.js';
import type { DocumentRequest } from './request.js';

// ---------------------------------------------------------------------------
// Candidate credential (defined first — used by DocumentRequestMatch below)
// ---------------------------------------------------------------------------

export interface CandidateCredential {
  credential: MatchableCredential;
  /** Index in the original credentials array */
  index: number;
  /** Which disclose field paths are present */
  disclosedFields: string[];
  /** Which disclose field paths are missing (non-optional) */
  missingFields: string[];
  /** Predicate condition IDs that are satisfiable */
  satisfiablePredicates: string[];
  /** Predicate condition IDs that are unsatisfiable */
  unsatisfiablePredicates: string[];
  /** Overall: all required disclose fields present + all predicates satisfiable */
  fullyQualified: boolean;
}

// ---------------------------------------------------------------------------
// Match result tree (mirrors the request tree structure)
// ---------------------------------------------------------------------------

export interface DocumentRequestMatch {
  type: 'DocumentRequest';
  request: DocumentRequest;
  candidates: CandidateCredential[];
  satisfied: boolean;
}

export interface LogicalRuleMatch {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: (LogicalRuleMatch | DocumentRequestMatch)[];
  satisfied: boolean;
}

export type RuleTreeMatch = LogicalRuleMatch | DocumentRequestMatch;

// ---------------------------------------------------------------------------
// User selection (input to resolvePresentation)
// ---------------------------------------------------------------------------

export interface CredentialSelection {
  docRequestID: string;
  credentialIndex: number;
}
