/**
 * Generic AND/OR tree evaluator. Reused for both:
 * - DocumentRequestNode trees (rules matching)
 * - DocumentConditionNode trees (condition coverage)
 */

export interface LogicalNode<T> {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: TreeNode<T>[];
}

export type TreeNode<T> = LogicalNode<T> | T;

export interface EvalResult<R> {
  satisfied: boolean;
  result: R;
}

/**
 * Evaluate a tree of AND/OR nodes. Each leaf is evaluated by `evalLeaf`.
 * Logical nodes are combined: AND = all satisfied, OR = any satisfied.
 */
export function evaluateTree<T, R>(
  node: TreeNode<T>,
  isLeaf: (n: TreeNode<T>) => n is T,
  evalLeaf: (leaf: T) => EvalResult<R>,
  combineLogical: (
    operator: 'AND' | 'OR',
    children: EvalResult<R>[],
  ) => EvalResult<R>,
): EvalResult<R> {
  if (isLeaf(node)) {
    return evalLeaf(node);
  }

  const logical = node as LogicalNode<T>;
  const childResults = logical.values.map((child) =>
    evaluateTree(child, isLeaf, evalLeaf, combineLogical),
  );

  return combineLogical(logical.operator, childResults);
}

/**
 * Default combiner for boolean satisfaction.
 * AND = all satisfied, OR = at least one satisfied.
 */
export function booleanCombine(
  operator: 'AND' | 'OR',
  children: EvalResult<boolean>[],
): EvalResult<boolean> {
  const satisfied =
    operator === 'AND'
      ? children.every((c) => c.satisfied)
      : children.some((c) => c.satisfied);
  return { satisfied, result: satisfied };
}
