import type { LocalizableString } from '../types/localization.js';
import type {
  VPRequest,
  VerifierInfo,
  DocumentRequestNode,
  DocumentRequest,
} from '../types/request.js';
import { DocumentRequestBuilder } from './document-request-builder.js';

/**
 * Fluent builder for VPRequest.
 *
 * Usage:
 *   new VPRequestBuilder('req-1')
 *     .setVerifier({ id: 'did:web:example', name: 'Example', url: 'https://example.com' })
 *     .setName('Verification Request')
 *     .addDocumentRequest(new DocumentRequestBuilder('dr1', 'CCCDCredential').disclose('c1', '$.credentialSubject.fullName').build())
 *     .build()
 */
export class VPRequestBuilder {
  private id: string;
  private version = '1.0';
  private name: LocalizableString = '';
  private nonce: string;
  private verifier!: VerifierInfo;
  private createdAt: string;
  private expiresAt?: string;
  private context?: string[];
  private rules?: DocumentRequestNode;
  private pendingDocRequests: DocumentRequest[] = [];

  constructor(id: string, nonce?: string) {
    this.id = id;
    this.nonce = nonce ?? crypto.randomUUID();
    this.createdAt = new Date().toISOString();
  }

  setVersion(version: string): this {
    this.version = version;
    return this;
  }

  setName(name: LocalizableString): this {
    this.name = name;
    return this;
  }

  setNonce(nonce: string): this {
    this.nonce = nonce;
    return this;
  }

  setVerifier(verifier: VerifierInfo): this {
    this.verifier = verifier;
    return this;
  }

  setCreatedAt(iso: string): this {
    this.createdAt = iso;
    return this;
  }

  setExpiresAt(iso: string): this {
    this.expiresAt = iso;
    return this;
  }

  setContext(context: string[]): this {
    this.context = context;
    return this;
  }

  /** Set the full rules tree directly */
  setRules(rules: DocumentRequestNode): this {
    this.rules = rules;
    return this;
  }

  /**
   * Add a single DocumentRequest. If multiple are added without an explicit
   * setRules(), they're combined with AND at build time.
   */
  addDocumentRequest(
    docRequest: DocumentRequest | DocumentRequestBuilder,
  ): this {
    const dr =
      docRequest instanceof DocumentRequestBuilder
        ? docRequest.build()
        : docRequest;
    this.pendingDocRequests.push(dr);
    return this;
  }

  build(): VPRequest {
    if (!this.verifier) {
      throw new Error('VPRequestBuilder: verifier is required');
    }

    let rules: DocumentRequestNode;
    if (this.rules) {
      rules = this.rules;
    } else if (this.pendingDocRequests.length === 1) {
      rules = this.pendingDocRequests[0];
    } else if (this.pendingDocRequests.length > 1) {
      rules = {
        type: 'Logical',
        operator: 'AND',
        values: this.pendingDocRequests,
      };
    } else {
      throw new Error('VPRequestBuilder: at least one document request or rules tree is required');
    }

    const req: VPRequest = {
      id: this.id,
      version: this.version,
      name: this.name,
      nonce: this.nonce,
      verifier: this.verifier,
      createdAt: this.createdAt,
      expiresAt: this.expiresAt ?? new Date(Date.now() + 30 * 60_000).toISOString(),
      rules,
    };

    if (this.context) {
      req['@context'] = this.context;
    }

    return req;
  }
}
