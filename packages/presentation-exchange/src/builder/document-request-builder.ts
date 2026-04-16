import type { LocalizableString } from '../types/localization.js';
import type {
  DocumentRequest,
  DocumentConditionNode,
  DiscloseCondition,
  ZKPCondition,
  ProofSystem,
  DisclosureMode,
} from '../types/request.js';

/**
 * Fluent builder for a single DocumentRequest node.
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

  private _requireHolderBinding = false;

  constructor(docRequestID: string, docType: string | string[]) {
    this.docRequestID = docRequestID;
    this.docType = Array.isArray(docType) ? docType : [docType];
  }

  /** Set the schema resolution strategy (e.g. 'JsonSchema', 'ICAO9303SOD') */
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

  /** Add a disclose condition (reveal a field) */
  disclose(
    conditionIDOrOpts: string | { field: string; id: string; optional?: boolean; purpose?: LocalizableString },
    field?: string,
    opts?: { optional?: boolean; purpose?: LocalizableString },
  ): this {
    let cond: DiscloseCondition;
    if (typeof conditionIDOrOpts === 'object') {
      cond = {
        type: 'DocumentCondition',
        conditionID: conditionIDOrOpts.id,
        field: conditionIDOrOpts.field,
        operator: 'disclose',
        ...(conditionIDOrOpts.optional !== undefined && { optional: conditionIDOrOpts.optional }),
        ...(conditionIDOrOpts.purpose !== undefined && { purpose: conditionIDOrOpts.purpose }),
      };
    } else {
      cond = {
        type: 'DocumentCondition',
        conditionID: conditionIDOrOpts,
        field: field!,
        operator: 'disclose',
        ...opts,
      };
    }
    this.conditions.push(cond);
    return this;
  }

  /** Add a ZKP condition */
  zkp(
    conditionID: string,
    opts: {
      circuitId: string;
      proofSystem: ProofSystem;
      privateInputs: Record<string, string>;
      publicInputs: Record<string, unknown>;
      purpose?: LocalizableString;
      circuitHash?: string;
      dependsOn?: Record<string, string>;
    },
  ): this {
    const cond: ZKPCondition = {
      type: 'DocumentCondition',
      conditionID,
      operator: 'zkp',
      ...opts,
    };
    this.conditions.push(cond);
    return this;
  }

  /** Require did-delegate "did" input to match the VP holder address. */
  requireHolderBinding(): this {
    this._requireHolderBinding = true;
    return this;
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
      ...(this._requireHolderBinding && { requireHolderBinding: true }),
    };
  }
}
