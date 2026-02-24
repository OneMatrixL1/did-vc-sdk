import type {
  DocumentConditionNode,
  DiscloseCondition,
  ZKPCondition,
} from '../types/request.js';

export interface ExtractedFields {
  disclose: DiscloseCondition[];
  zkp: ZKPCondition[];
}

/**
 * Walk a condition tree (AND-by-default array or nested Logical nodes)
 * and collect all leaf conditions by type.
 */
export function extractConditions(
  conditions: DocumentConditionNode[],
): ExtractedFields {
  const result: ExtractedFields = { disclose: [], zkp: [] };
  for (const cond of conditions) {
    walkCondition(cond, result);
  }
  return result;
}

function walkCondition(
  node: DocumentConditionNode,
  acc: ExtractedFields,
): void {
  if (node.type === 'Logical') {
    for (const child of node.values) {
      walkCondition(child, acc);
    }
    return;
  }

  // Leaf condition
  if (node.operator === 'disclose') {
    acc.disclose.push(node as DiscloseCondition);
  } else if (node.operator === 'zkp') {
    acc.zkp.push(node as ZKPCondition);
  }
}
