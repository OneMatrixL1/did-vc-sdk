declare module 'jsonld-signatures' {
  interface ProofPurposeOptions {
    domain?: string;
    challenge?: string;
  }

  interface ProofPurpose {
    term: string;
  }

  const purposes: {
    AssertionProofPurpose: new (options: ProofPurposeOptions) => ProofPurpose;
  };

  export default { purposes };
}
