import type { LocalizableString } from './localization.js';

// ---------------------------------------------------------------------------
// Top-level request
// ---------------------------------------------------------------------------

export interface VPRequest {
  id: string;
  version: string;
  name: LocalizableString;
  nonce: string;
  verifier: VerifierInfo;
  createdAt: string;
  expiresAt: string;
  '@context'?: string[];
  rules: DocumentRequestNode;
}

export interface VerifierInfo {
  id: string;
  name: LocalizableString;
  url: string;
}

// ---------------------------------------------------------------------------
// Rules tree (recursive)
// ---------------------------------------------------------------------------

export type DocumentRequestNode = LogicalRequestNode | DocumentRequest;

export interface LogicalRequestNode {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: DocumentRequestNode[];
}

export interface DocumentRequest {
  type: 'DocumentRequest';
  docRequestID: string;
  docType: string[];
  issuer?: string | string[];
  name?: LocalizableString;
  purpose?: LocalizableString;
  conditions: DocumentConditionNode[];
}

// ---------------------------------------------------------------------------
// Conditions tree (per credential)
// ---------------------------------------------------------------------------

export type DocumentConditionNode =
  | LogicalConditionNode
  | DiscloseCondition
  | ZKPCondition;

export interface LogicalConditionNode {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: DocumentConditionNode[];
}

export interface DiscloseCondition {
  type: 'DocumentCondition';
  conditionID: string;
  field: string;
  operator: 'disclose';
  optional?: boolean;
  purpose?: LocalizableString;
}

export interface ZKPCondition {
  type: 'DocumentCondition';
  conditionID: string;
  operator: 'zkp';
  circuitId: string;
  proofSystem: ProofSystem;
  purpose?: LocalizableString;
  circuitHash?: string;
  privateInputs: Record<string, string>;
  publicInputs: Record<string, unknown>;
  dependsOn?: Record<string, string>;
}

export type ProofSystem = 'groth16' | 'plonk' | 'fflonk' | 'halo2' | 'stark' | (string & {});
