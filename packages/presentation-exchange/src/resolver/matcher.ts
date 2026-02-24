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
import { resolveJsonPath } from '../utils/jsonpath.js';
import { extractConditions } from './field-extractor.js';

/**
 * Match available credentials against a VPRequest's rule tree.
 * Returns an annotated match tree that mirrors the request structure,
 * suitable for UI rendering (show what's needed, what matches, where choices exist).
 */
export function matchCredentials(
  rules: DocumentRequestNode,
  credentials: MatchableCredential[],
): RuleTreeMatch {
  return matchNode(rules, credentials);
}

function matchNode(
  node: DocumentRequestNode,
  credentials: MatchableCredential[],
): RuleTreeMatch {
  if (node.type === 'Logical') {
    const children = node.values.map((child) => matchNode(child, credentials));
    const satisfied =
      node.operator === 'AND'
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
  return matchDocumentRequest(node, credentials);
}

function matchDocumentRequest(
  request: DocumentRequest,
  credentials: MatchableCredential[],
): DocumentRequestMatch {
  const candidates: CandidateCredential[] = [];

  for (let i = 0; i < credentials.length; i++) {
    const cred = credentials[i];

    // 1. Filter by docType: credential must have at least one matching type
    const credTypes = cred.type as readonly string[];
    const hasMatchingType = request.docType.some((dt) =>
      credTypes.indexOf(dt) !== -1,
    );
    if (!hasMatchingType) continue;

    // 2. Filter by issuer (if specified)
    if (request.issuer !== undefined) {
      const credIssuerId = getCredentialIssuerId(cred);
      const allowedIssuers = Array.isArray(request.issuer)
        ? request.issuer
        : [request.issuer];
      if (!allowedIssuers.includes(credIssuerId)) continue;
    }

    // 3. Check field coverage
    const { disclose, zkp } = extractConditions(request.conditions);

    // Get the subject object for field resolution
    const subject = Array.isArray(cred.credentialSubject)
      ? cred.credentialSubject[0]
      : cred.credentialSubject;

    // Wrap in a credential-shaped object so JSONPath from root works
    const credObj = { ...cred, credentialSubject: subject };

    const disclosedFields: string[] = [];
    const missingFields: string[] = [];
    for (const dc of disclose) {
      const { found } = resolveJsonPath(credObj, dc.field);
      if (found) {
        disclosedFields.push(dc.field);
      } else if (!dc.optional) {
        missingFields.push(dc.field);
      }
    }

    const satisfiableZKPs: string[] = [];
    const unsatisfiableZKPs: string[] = [];
    for (const zc of zkp) {
      const allInputsResolvable = Object.values(zc.privateInputs).every(
        (path) => resolveJsonPath(credObj, path).found,
      );
      if (allInputsResolvable) {
        satisfiableZKPs.push(zc.conditionID);
      } else {
        unsatisfiableZKPs.push(zc.conditionID);
      }
    }

    const fullyQualified =
      missingFields.length === 0 && unsatisfiableZKPs.length === 0;

    candidates.push({
      credential: cred,
      index: i,
      disclosedFields,
      missingFields,
      satisfiableZKPs,
      unsatisfiableZKPs,
      fullyQualified,
    });
  }

  return {
    type: 'DocumentRequest',
    request,
    candidates,
    satisfied: candidates.some((c) => c.fullyQualified),
  };
}
