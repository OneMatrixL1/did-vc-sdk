import type { LocalizableString } from '../types/localization.js';
import type { PresentedCredential } from '../types/response.js';
import type {
  VPRequest,
  VerifierRequestProof,
  DocumentRequestNode,
  DocumentRequest,
  KeyDoc,
} from '../types/request.js';
import { DocumentRequestBuilder } from './document-request-builder.js';
import { signPresentation } from '@1matrix/credential-sdk/vc';
import jsigs from 'jsonld-signatures';

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

  private version = '2.0';

  private name: LocalizableString = '';

  private nonce: string;

  private verifierId?: string;

  private verifierName: LocalizableString = '';

  private verifierUrl?: string;

  private verifierCredentials: PresentedCredential[] = [];

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

  /** Same call-site shape as before: `{ id, name, url }`. */
  setVerifier(verifier: { id: string; name: LocalizableString; url: string }): this {
    this.verifierId = verifier.id;
    this.verifierName = verifier.name;
    this.verifierUrl = verifier.url;
    return this;
  }

  addVerifierCredential(credential: PresentedCredential): this {
    this.verifierCredentials.push(credential);
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
    const dr = docRequest instanceof DocumentRequestBuilder
      ? docRequest.build()
      : docRequest;
    this.pendingDocRequests.push(dr);
    return this;
  }

  /** Build an unsigned VPRequest (no proof). */
  build(): VPRequest {
    if (!this.verifierId) {
      throw new Error('VPRequestBuilder: verifier is required');
    }

    let rules: DocumentRequestNode;
    if (this.rules) {
      rules = this.rules;
    } else if (this.pendingDocRequests.length === 1) {
      rules = this.pendingDocRequests[0]!;
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
      type: ['VerifiablePresentationRequest'],
      id: this.id,
      version: this.version,
      name: this.name,
      nonce: this.nonce,
      verifier: this.verifierId,
      verifierName: this.verifierName,
      verifierUrl: this.verifierUrl!,
      createdAt: this.createdAt,
      expiresAt: this.expiresAt ?? new Date(Date.now() + 30 * 60_000).toISOString(),
      rules,
    };

    if (this.verifierCredentials.length > 0) {
      req.verifierCredentials = this.verifierCredentials;
    }

    if (this.context) {
      req['@context'] = this.context;
    }

    return req;
  }

  /**
   * Build and sign the VPRequest using credential-sdk's `signPresentation`.
   *
   * Uses `AssertionProofPurpose` (not `authentication`) so that
   * `verifyVPRequest` accepts the proof envelope.
   *
   * @param keyDoc  Key document with `id`, `type`, `keypair`, and `controller`.
   * @param resolver  Optional DID resolver forwarded to credential-sdk.
   */
  async buildSigned(
    keyDoc: KeyDoc,
    resolver?: unknown,
  ): Promise<VPRequest> {
    const unsigned = this.build();

    const domain = new URL(unsigned.verifierUrl).hostname;
    const challenge = unsigned.nonce;

    // Wrap the request as a VP-like LD document so signPresentation can sign it.
    const vpLikeDoc = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        ...(unsigned['@context'] ?? []),
      ],
      ...unsigned,
      type: ['VerifiablePresentation'],
      holder: unsigned.verifier,
    };

    const { AssertionProofPurpose } = jsigs.purposes;
    const purpose = new AssertionProofPurpose({ domain, challenge });

    const signed = await signPresentation(
      vpLikeDoc,
      keyDoc,
      challenge,
      domain,
      resolver ?? null,
      true,    // compactProof
      purpose,
      false,   // addSuiteContext — avoid redefining credentials/v1 terms
    );

    const proof = (signed as Record<string, unknown>).proof as VerifierRequestProof;
    return { ...unsigned, proof };
  }
}
