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
    conditionID: string,
    field: string,
    opts?: {
      optional?: boolean;
      purpose?: LocalizableString;
      merkleDisclosure?: { commitmentRef: string };
    },
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

  /** Add a Merkle-backed disclose condition (DG13 field-level selective disclosure) */
  merkleDisclose(
    conditionID: string,
    field: string,
    commitmentRef: string,
    opts?: { optional?: boolean; purpose?: LocalizableString },
  ): this {
    return this.disclose(conditionID, field, {
      ...opts,
      merkleDisclosure: { commitmentRef },
    });
  }

  /** Add a ZKP condition */
  zkp(
    conditionID: string,
    opts: {
      circuitId: string;
      proofSystem: ProofSystem;
      publicInputs?: Record<string, unknown>;
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
}
