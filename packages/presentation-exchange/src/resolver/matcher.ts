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
import type { SchemaResolverMap } from '../types/schema-resolver.js';
import { defaultResolvers } from '../resolvers/index.js';
import { extractConditions } from './field-extractor.js';

/**
 * Match available credentials against a VPRequest's rule tree.
 * Returns an annotated match tree that mirrors the request structure,
 * suitable for UI rendering (show what's needed, what matches, where choices exist).
 *
 * @param resolvers  Optional — extra or overriding resolvers merged on top of
 *                   the built-in defaults (JsonSchema + ICAO9303SOD).
 */
export function matchCredentials(
  rules: DocumentRequestNode,
  credentials: MatchableCredential[],
  resolvers?: SchemaResolverMap,
): RuleTreeMatch {
  const merged = { ...defaultResolvers, ...resolvers };
  return matchNode(rules, credentials, merged);
}

function matchNode(
  node: DocumentRequestNode,
  credentials: MatchableCredential[],
  resolvers: SchemaResolverMap,
): RuleTreeMatch {
  if (node.type === 'Logical') {
    const children = node.values.map((child) => matchNode(child, credentials, resolvers));
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

  // Leaf: DocumentRequest
  return matchDocumentRequest(node, credentials, resolvers);
}

function checkFieldCoverage(
  request: DocumentRequest,
  credential: MatchableCredential,
  resolvers: SchemaResolverMap,
): Pick<CandidateCredential, 'disclosedFields' | 'missingFields' | 'satisfiableZKPs' | 'unsatisfiableZKPs'> {
  const resolver = resolvers[request.schemaType];
  if (!resolver) {
    throw new Error(
      `No SchemaResolver registered for schemaType "${request.schemaType}". ` +
      `Available resolvers: [${Object.keys(resolvers).join(', ')}]`,
    );
  }

  const { disclose, zkp } = extractConditions(request.conditions);

  const disclosedFields: string[] = [];
  const missingFields: string[] = [];
  for (const dc of disclose) {
    const { found } = resolver.resolveField(credential, dc.field);
    if (found) {
      disclosedFields.push(dc.field);
    } else if (!dc.optional) {
      missingFields.push(dc.field);
    }
  }

  const satisfiableZKPs: string[] = zkp.map((zc) => zc.conditionID);
  const unsatisfiableZKPs: string[] = [];

  return {
    disclosedFields, missingFields, satisfiableZKPs, unsatisfiableZKPs,
  };
}

function matchSingleCredential(
  request: DocumentRequest,
  cred: MatchableCredential,
  index: number,
  resolvers: SchemaResolverMap,
): CandidateCredential | null {
  // 1. Filter by docType
  const credTypes = cred.type as readonly string[];
  if (!request.docType.some((dt) => credTypes.indexOf(dt) !== -1)) {
    return null;
  }

  // 2. Filter by issuer (if specified)
  if (request.issuer !== undefined) {
    const allowedIssuers = Array.isArray(request.issuer) ? request.issuer : [request.issuer];
    if (!allowedIssuers.includes(getCredentialIssuerId(cred))) {
      return null;
    }
  }

  // 3. Full-document mode: skip field coverage entirely
  if (request.disclosureMode === 'full') {
    return {
      credential: cred,
      index,
      disclosedFields: [],
      missingFields: [],
      satisfiableZKPs: [],
      unsatisfiableZKPs: [],
      fullyQualified: true,
    };
  }

  // 4. Selective mode: check field coverage via schema resolver
  const coverage = checkFieldCoverage(request, cred, resolvers);

  return {
    credential: cred,
    index,
    ...coverage,
    fullyQualified: coverage.missingFields.length === 0 && coverage.unsatisfiableZKPs.length === 0,
  };
}

function matchDocumentRequest(
  request: DocumentRequest,
  credentials: MatchableCredential[],
  resolvers: SchemaResolverMap,
): DocumentRequestMatch {
  const candidates = credentials
    .map((cred, i) => matchSingleCredential(request, cred, i, resolvers))
    .filter((c): c is CandidateCredential => c !== null);

  return {
    type: 'DocumentRequest',
    request,
    candidates,
    satisfied: candidates.some((c) => c.fullyQualified),
  };
}
