import type { MatchableCredential } from '../types/credential.js';
import { getCredentialIssuerId } from '../types/credential.js';
import type {
  DocumentRequestNode,
  DocumentRequest,
} from '../types/request.js';
import type {
  RuleTreeMatch,
  LogicalRuleMatch,
  DocumentRequestMatch,
  CandidateCredential,
} from '../types/matching.js';
import type { ProofSystemMap } from '../types/proof-system.js';
import { defaultProofSystems } from '../proof-system/index.js';
import { extractConditions } from './field-extractor.js';

/**
 * Match available credentials against a VPRequest's rule tree.
 * Returns an annotated match tree that mirrors the request structure,
 * suitable for UI rendering (show what's needed, what matches, where choices exist).
 */
export function matchCredentials(
  rules: DocumentRequestNode,
  credentials: MatchableCredential[],
  proofSystems?: ProofSystemMap,
): RuleTreeMatch {
  const merged = { ...defaultProofSystems, ...proofSystems };
  return matchNode(rules, credentials, merged);
}

function matchNode(
  node: DocumentRequestNode,
  credentials: MatchableCredential[],
  systems: ProofSystemMap,
): RuleTreeMatch {
  if (node.type === 'Logical') {
    const children = node.values.map((child) => matchNode(child, credentials, systems));
    const satisfied = node.operator === 'AND'
      ? children.every((c) => c.satisfied)
      : children.some((c) => c.satisfied);

    return {
      type: 'Logical',
      operator: node.operator,
      values: children,
      satisfied,
    } satisfies LogicalRuleMatch;
  }

  return matchDocumentRequest(node, credentials, systems);
}

function checkFieldCoverage(
  request: DocumentRequest,
  credential: MatchableCredential,
  systems: ProofSystemMap,
): Pick<CandidateCredential, 'disclosedFields' | 'missingFields' | 'satisfiablePredicates' | 'unsatisfiablePredicates'> {
  const system = systems[request.schemaType];
  if (!system) {
    throw new Error(
      `No SchemaProofSystem registered for schemaType "${request.schemaType}". ` +
      `Available: [${Object.keys(systems).join(', ')}]`,
    );
  }

  const { disclose, predicates } = extractConditions(request.conditions);

  const disclosedFields: string[] = [];
  const missingFields: string[] = [];
  for (const dc of disclose) {
    const { found } = system.resolveField(credential, dc.field);
    if (found) {
      disclosedFields.push(dc.field);
    } else if (!dc.optional) {
      missingFields.push(dc.field);
    }
  }

  // Predicates are always satisfiable at match time —
  // actual satisfiability is checked at prove time.
  const satisfiablePredicates: string[] = predicates.map((p) => p.conditionID);
  const unsatisfiablePredicates: string[] = [];

  return { disclosedFields, missingFields, satisfiablePredicates, unsatisfiablePredicates };
}

function matchSingleCredential(
  request: DocumentRequest,
  cred: MatchableCredential,
  index: number,
  systems: ProofSystemMap,
): CandidateCredential | null {
  const credTypes = cred.type as readonly string[];
  if (!request.docType.some((dt) => credTypes.indexOf(dt) !== -1)) {
    return null;
  }

  if (request.issuer !== undefined) {
    const allowedIssuers = Array.isArray(request.issuer) ? request.issuer : [request.issuer];
    if (!allowedIssuers.includes(getCredentialIssuerId(cred))) {
      return null;
    }
  }

  if (request.disclosureMode === 'full') {
    return {
      credential: cred,
      index,
      disclosedFields: [],
      missingFields: [],
      satisfiablePredicates: [],
      unsatisfiablePredicates: [],
      fullyQualified: true,
    };
  }

  const coverage = checkFieldCoverage(request, cred, systems);

  return {
    credential: cred,
    index,
    ...coverage,
    fullyQualified: coverage.missingFields.length === 0 && coverage.unsatisfiablePredicates.length === 0,
  };
}

function matchDocumentRequest(
  request: DocumentRequest,
  credentials: MatchableCredential[],
  systems: ProofSystemMap,
): DocumentRequestMatch {
  const candidates = credentials
    .map((cred, i) => matchSingleCredential(request, cred, i, systems))
    .filter((c): c is CandidateCredential => c !== null);

  return {
    type: 'DocumentRequest',
    request,
    candidates,
    satisfied: candidates.some((c) => c.fullyQualified),
  };
}
