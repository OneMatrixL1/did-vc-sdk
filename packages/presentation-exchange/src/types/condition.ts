import type { LocalizableString } from './localization.js';

// ---------------------------------------------------------------------------
// Predicate operators
// ---------------------------------------------------------------------------

export type PredicateOperator =
  | 'greaterThan'
  | 'lessThan'
  | 'greaterThanOrEqual'
  | 'lessThanOrEqual'
  | 'inRange'
  | 'equals';

// ---------------------------------------------------------------------------
// Predicate condition — replaces ZKPCondition for end users
// ---------------------------------------------------------------------------

export interface PredicateCondition {
  type: 'DocumentCondition';
  conditionID: string;
  operator: PredicateOperator;
  field: string;
  optional?: boolean;
  purpose?: LocalizableString;
  /** Predicate parameters — meaning depends on operator */
  params: PredicateParams;
}

export type PredicateParams =
  | { value: string }                              // greaterThan, lessThan, etc.
  | { gte: string; lte: string }                   // inRange
  | { value: string }                              // equals (known value)
  | { ref: string };                               // equals (cross-doc reference)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function isPredicateCondition(
  node: unknown,
): node is PredicateCondition {
  if (!node || typeof node !== 'object') return false;
  const n = node as Record<string, unknown>;
  return n.type === 'DocumentCondition'
    && typeof n.operator === 'string'
    && ['greaterThan', 'lessThan', 'greaterThanOrEqual', 'lessThanOrEqual', 'inRange', 'equals'].includes(n.operator as string);
}
