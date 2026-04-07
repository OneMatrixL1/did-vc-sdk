import type {
  DocumentConditionNode,
  DiscloseCondition,
} from '../types/request.js';
import type { PredicateCondition } from '../types/condition.js';
import { isPredicateCondition } from '../types/condition.js';

export interface ExtractedConditions {
  disclose: DiscloseCondition[];
  predicates: PredicateCondition[];
}

/**
 * Walk a condition tree (AND-by-default array or nested Logical nodes)
 * and collect all leaf conditions by type.
 */
export function extractConditions(
  conditions: DocumentConditionNode[],
): ExtractedConditions {
  const result: ExtractedConditions = { disclose: [], predicates: [] };
  for (const cond of conditions) {
    walkCondition(cond, result);
  }
  return result;
}

function walkCondition(
  node: DocumentConditionNode,
  acc: ExtractedConditions,
): void {
  if (node.type === 'Logical') {
    for (const child of node.values) {
      walkCondition(child, acc);
    }
    return;
  }

  if (node.operator === 'disclose') {
    acc.disclose.push(node as DiscloseCondition);
  } else if (isPredicateCondition(node)) {
    acc.predicates.push(node);
  }
}
