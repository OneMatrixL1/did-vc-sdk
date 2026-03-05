import type { LocalizableString } from './localization.js';

// ---------------------------------------------------------------------------
// Verifier info (defined before VPRequest which references it)
// ---------------------------------------------------------------------------

export interface VerifierInfo {
  id: string;
  name: LocalizableString;
  url: string;
}

// ---------------------------------------------------------------------------
// Proof system & conditions (defined before DocumentRequest which uses them)
// ---------------------------------------------------------------------------

export type ProofSystem = 'groth16' | 'plonk' | 'fflonk' | 'halo2' | 'stark' | (string & {});

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

export interface LogicalConditionNode {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: (LogicalConditionNode | DiscloseCondition | ZKPCondition)[];
}

export type DocumentConditionNode =
  | LogicalConditionNode
  | DiscloseCondition
  | ZKPCondition;

// ---------------------------------------------------------------------------
// Rules tree (recursive)
// ---------------------------------------------------------------------------

export type DisclosureMode = 'selective' | 'full';

export interface DocumentRequest {
  type: 'DocumentRequest';
  docRequestID: string;
  docType: string[];
  issuer?: string | string[];
  name?: LocalizableString;
  purpose?: LocalizableString;
  /**
   * 'selective' (default) — only disclosed fields / ZKP proofs are included.
   * 'full'                — entire credential is passed verbatim; conditions are ignored.
   *                         Trusted-verifier enforcement will be layered on top in a future release.
   */
  disclosureMode?: DisclosureMode;
  conditions: DocumentConditionNode[];
}

/**
 * LogicalRequestNode.values uses an inline union instead of the DocumentRequestNode
 * type alias to avoid a circular forward reference.
 */
export interface LogicalRequestNode {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: (LogicalRequestNode | DocumentRequest)[];
}

export type DocumentRequestNode = LogicalRequestNode | DocumentRequest;

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
