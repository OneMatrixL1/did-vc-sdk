/**
 * Representation of an RSA Key Delegation Certificate.
 * Binds the holder's DID to the chip's DID via an Active Authentication signature.
 */
export interface DelegationCertificate {
  /** The holder's DID (did:ethr:...) */
  holderDID: string;
  /** The chip's DID (did:key:z... derived from DG15) */
  chipDID: string;
  /** The timestamp of the delegation (ISO 8601 string) */
  timestamp: string;
  /** The RSA signature from the chip (base64) */
  aaSignature: string;
}
