import type { LocalizableString } from '../types/localization.js';
import type {
  DocumentRequest,
  DocumentConditionNode,
  DiscloseCondition,
  DisclosureMode,
} from '../types/request.js';
import type { PredicateCondition, PredicateOperator } from '../types/condition.js';

// ---------------------------------------------------------------------------
// Option types
// ---------------------------------------------------------------------------

interface BaseOpts {
  /** Condition ID. Defaults to `field` when omitted. */
  id?: string;
  optional?: boolean;
  purpose?: LocalizableString;
}

interface DiscloseOpts extends BaseOpts {
  field: string;
}

interface ThresholdOpts extends BaseOpts {
  field: string;
  value: string;
}

interface RangeOpts extends BaseOpts {
  field: string;
  gte: string;
  lte: string;
}

type EqualsOpts = BaseOpts & { field: string } & ({ value: string } | { ref: string });

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/**
 * Fluent builder for a single DocumentRequest node.
 *
 * All condition methods accept an object. `id` is optional — defaults to `field`.
 *
 * @example
 *   new DocumentRequestBuilder('cccd', 'CCCDCredential')
 *     .setSchemaType('ICAO9303SOD')
 *     .disclose({ field: 'fullName' })
 *     .disclose({ field: 'gender', id: 'c2' })
 *     .inRange({ field: 'dateOfBirth', gte: '19900101', lte: '20061231' })
 *     .equals({ field: 'fullName', ref: 'parent.fullName' })
 *     .build()
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
  disclose(opts: DiscloseOpts): this {
    const cond: DiscloseCondition = {
      type: 'DocumentCondition',
      conditionID: opts.id ?? opts.field,
      field: opts.field,
      operator: 'disclose',
      ...(opts.optional !== undefined && { optional: opts.optional }),
      ...(opts.purpose !== undefined && { purpose: opts.purpose }),
    };
    this.conditions.push(cond);
    return this;
  }

  /** Prove field value > threshold without revealing it. */
  greaterThan(opts: ThresholdOpts): this {
    return this.addPredicate('greaterThan', opts.field, { value: opts.value }, opts);
  }

  /** Prove field value < threshold without revealing it. */
  lessThan(opts: ThresholdOpts): this {
    return this.addPredicate('lessThan', opts.field, { value: opts.value }, opts);
  }

  /** Prove field value >= threshold without revealing it. */
  greaterThanOrEqual(opts: ThresholdOpts): this {
    return this.addPredicate('greaterThanOrEqual', opts.field, { value: opts.value }, opts);
  }

  /** Prove field value <= threshold without revealing it. */
  lessThanOrEqual(opts: ThresholdOpts): this {
    return this.addPredicate('lessThanOrEqual', opts.field, { value: opts.value }, opts);
  }

  /** Prove field value is within a range without revealing it. */
  inRange(opts: RangeOpts): this {
    return this.addPredicate('inRange', opts.field, { gte: opts.gte, lte: opts.lte }, opts);
  }

  /** Prove field equals a known value or a cross-doc reference without revealing it. */
  equals(opts: EqualsOpts): this {
    const params = 'ref' in opts ? { ref: opts.ref } : { value: opts.value };
    return this.addPredicate('equals', opts.field, params, opts);
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
    operator: PredicateOperator,
    field: string,
    params: Record<string, unknown>,
    opts: BaseOpts,
  ): this {
    const cond: PredicateCondition = {
      type: 'DocumentCondition',
      conditionID: opts.id ?? field,
      operator,
      field,
      params: params as PredicateCondition['params'],
      ...(opts.optional !== undefined && { optional: opts.optional }),
      ...(opts.purpose !== undefined && { purpose: opts.purpose }),
    };
    this.conditions.push(cond);
    return this;
  }
}
