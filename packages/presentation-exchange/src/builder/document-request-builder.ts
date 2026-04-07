import type { LocalizableString } from '../types/localization.js';
import type {
  DocumentRequest,
  DocumentConditionNode,
  DiscloseCondition,
  DisclosureMode,
} from '../types/request.js';
import type { PredicateCondition, PredicateOperator } from '../types/condition.js';

/**
 * Fluent builder for a single DocumentRequest node.
 *
 * Developers use high-level methods — the SDK maps them to circuits internally:
 *   .disclose()     → field-reveal circuit
 *   .greaterThan()  → date-greaterthan circuit
 *   .inRange()      → date-inrange circuit
 *   .equals()       → field-equals circuit
 */
export class DocumentRequestBuilder {
  private docRequestID: string;
  private docType: string[];
  private schemaType?: string;
  private issuer?: string | string[];
  private name?: LocalizableString;
  private purpose?: LocalizableString;
  private disclosureMode?: DisclosureMode;
  private conditions: DocumentConditionNode[] = [];

  constructor(docRequestID: string, docType: string | string[]) {
    this.docRequestID = docRequestID;
    this.docType = Array.isArray(docType) ? docType : [docType];
  }

  /** Set the schema resolution strategy (e.g. 'ICAO9303SOD', 'BBS') */
  setSchemaType(type: string): this {
    this.schemaType = type;
    return this;
  }

  setIssuer(issuer: string | string[]): this {
    this.issuer = issuer;
    return this;
  }

  setName(name: LocalizableString): this {
    this.name = name;
    return this;
  }

  setPurpose(purpose: LocalizableString): this {
    this.purpose = purpose;
    return this;
  }

  setDisclosureMode(mode: DisclosureMode): this {
    this.disclosureMode = mode;
    return this;
  }

  /** Reveal a field value to the verifier. */
  disclose(
    conditionID: string,
    field: string,
    opts?: { optional?: boolean; purpose?: LocalizableString },
  ): this {
    const cond: DiscloseCondition = {
      type: 'DocumentCondition',
      conditionID,
      field,
      operator: 'disclose',
      ...opts,
    };
    this.conditions.push(cond);
    return this;
  }

  /** Prove field value > threshold without revealing it. */
  greaterThan(
    conditionID: string,
    field: string,
    opts: { value: string; optional?: boolean; purpose?: LocalizableString },
  ): this {
    return this.addPredicate(conditionID, 'greaterThan', field, { value: opts.value }, opts);
  }

  /** Prove field value < threshold without revealing it. */
  lessThan(
    conditionID: string,
    field: string,
    opts: { value: string; optional?: boolean; purpose?: LocalizableString },
  ): this {
    return this.addPredicate(conditionID, 'lessThan', field, { value: opts.value }, opts);
  }

  /** Prove field value >= threshold without revealing it. */
  greaterThanOrEqual(
    conditionID: string,
    field: string,
    opts: { value: string; optional?: boolean; purpose?: LocalizableString },
  ): this {
    return this.addPredicate(conditionID, 'greaterThanOrEqual', field, { value: opts.value }, opts);
  }

  /** Prove field value <= threshold without revealing it. */
  lessThanOrEqual(
    conditionID: string,
    field: string,
    opts: { value: string; optional?: boolean; purpose?: LocalizableString },
  ): this {
    return this.addPredicate(conditionID, 'lessThanOrEqual', field, { value: opts.value }, opts);
  }

  /** Prove field value is within a range without revealing it. */
  inRange(
    conditionID: string,
    field: string,
    opts: { gte: string; lte: string; optional?: boolean; purpose?: LocalizableString },
  ): this {
    return this.addPredicate(conditionID, 'inRange', field, { gte: opts.gte, lte: opts.lte }, opts);
  }

  /** Prove field equals a known value or a cross-doc reference without revealing it. */
  equals(
    conditionID: string,
    field: string,
    opts: ({ value: string } | { ref: string }) & { optional?: boolean; purpose?: LocalizableString },
  ): this {
    const params = 'ref' in opts ? { ref: opts.ref } : { value: opts.value };
    return this.addPredicate(conditionID, 'equals', field, params, opts);
  }

  /** Add a raw condition node (for logical groupings) */
  addCondition(condition: DocumentConditionNode): this {
    this.conditions.push(condition);
    return this;
  }

  build(): DocumentRequest {
    if (!this.schemaType) {
      throw new Error(
        `DocumentRequestBuilder "${this.docRequestID}": schemaType is required. ` +
        'Call setSchemaType() before build().',
      );
    }

    return {
      type: 'DocumentRequest',
      docRequestID: this.docRequestID,
      docType: this.docType,
      schemaType: this.schemaType,
      ...(this.issuer !== undefined && { issuer: this.issuer }),
      ...(this.name !== undefined && { name: this.name }),
      ...(this.purpose !== undefined && { purpose: this.purpose }),
      ...(this.disclosureMode !== undefined && { disclosureMode: this.disclosureMode }),
      conditions: this.conditions,
    };
  }

  private addPredicate(
    conditionID: string,
    operator: PredicateOperator,
    field: string,
    params: Record<string, unknown>,
    opts?: { optional?: boolean; purpose?: LocalizableString },
  ): this {
    const cond: PredicateCondition = {
      type: 'DocumentCondition',
      conditionID,
      operator,
      field,
      params: params as PredicateCondition['params'],
      ...(opts?.optional !== undefined && { optional: opts.optional }),
      ...(opts?.purpose !== undefined && { purpose: opts.purpose }),
    };
    this.conditions.push(cond);
    return this;
  }
}
