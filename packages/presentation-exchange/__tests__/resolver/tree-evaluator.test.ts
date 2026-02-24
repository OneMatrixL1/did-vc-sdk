import { describe, it, expect } from 'vitest';
import { evaluateTree, booleanCombine } from '../../src/resolver/tree-evaluator.js';
import type { TreeNode, EvalResult } from '../../src/resolver/tree-evaluator.js';

type Leaf = { type: 'leaf'; value: boolean };
type TestNode = TreeNode<Leaf>;

const isLeaf = (n: TestNode): n is Leaf => (n as Leaf).type === 'leaf';
const evalLeaf = (leaf: Leaf): EvalResult<boolean> => ({
  satisfied: leaf.value,
  result: leaf.value,
});

describe('evaluateTree', () => {
  it('evaluates a single true leaf', () => {
    const node: TestNode = { type: 'leaf', value: true };
    const result = evaluateTree(node, isLeaf, evalLeaf, booleanCombine);
    expect(result.satisfied).toBe(true);
  });

  it('evaluates AND(true, true) = true', () => {
    const node: TestNode = {
      type: 'Logical',
      operator: 'AND',
      values: [
        { type: 'leaf', value: true },
        { type: 'leaf', value: true },
      ],
    };
    const result = evaluateTree(node, isLeaf, evalLeaf, booleanCombine);
    expect(result.satisfied).toBe(true);
  });

  it('evaluates AND(true, false) = false', () => {
    const node: TestNode = {
      type: 'Logical',
      operator: 'AND',
      values: [
        { type: 'leaf', value: true },
        { type: 'leaf', value: false },
      ],
    };
    const result = evaluateTree(node, isLeaf, evalLeaf, booleanCombine);
    expect(result.satisfied).toBe(false);
  });

  it('evaluates OR(false, true) = true', () => {
    const node: TestNode = {
      type: 'Logical',
      operator: 'OR',
      values: [
        { type: 'leaf', value: false },
        { type: 'leaf', value: true },
      ],
    };
    const result = evaluateTree(node, isLeaf, evalLeaf, booleanCombine);
    expect(result.satisfied).toBe(true);
  });

  it('evaluates OR(false, false) = false', () => {
    const node: TestNode = {
      type: 'Logical',
      operator: 'OR',
      values: [
        { type: 'leaf', value: false },
        { type: 'leaf', value: false },
      ],
    };
    const result = evaluateTree(node, isLeaf, evalLeaf, booleanCombine);
    expect(result.satisfied).toBe(false);
  });

  it('evaluates nested AND(OR(false, true), true) = true', () => {
    const node: TestNode = {
      type: 'Logical',
      operator: 'AND',
      values: [
        {
          type: 'Logical',
          operator: 'OR',
          values: [
            { type: 'leaf', value: false },
            { type: 'leaf', value: true },
          ],
        },
        { type: 'leaf', value: true },
      ],
    };
    const result = evaluateTree(node, isLeaf, evalLeaf, booleanCombine);
    expect(result.satisfied).toBe(true);
  });
});
