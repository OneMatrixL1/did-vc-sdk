/**
 * ZKP-backed ICAO schema resolver for field-level selective disclosure.
 *
 * Each ZKP condition → 1 ZKPProof (sod, dg13, predicate — all same type).
 * Each disclosed DG13 field → 1 MerkleDisclosureProof.
 * Dependencies are expressed via dependsOn on each proof.
 */

import type { MatchableCredential } from '../types/credential.js';
import type { CredentialProof, ZKPProof } from '../types/credential.js';
import type { MerkleDisclosureProof } from '../types/merkle.js';
import type { PresentedCredential } from '../types/response.js';
import type { DiscloseCondition, ZKPCondition } from '../types/request.js';
import type { MerkleWitnessData } from '../types/merkle.js';
import type { ZKPProvider } from '../types/zkp-provider.js';
import type { SchemaResolver, DeriveOptions } from '../types/schema-resolver.js';
import { createICAOSchemaResolver } from './icao-schema-resolver.js';
import { fieldIdToLeafIndex, extractSiblingsForLeaf, isDg13Field } from './zkp-field-mapping.js';

export interface ZKPDeriveOptions extends DeriveOptions {
  verifierId?: string;

  zkpProvider?: ZKPProvider;
}

export interface ZKPSchemaResolver extends SchemaResolver {
  deriveCredentialWithZKP(
    credential: MatchableCredential,
    discloseConditions: DiscloseCondition[],
    zkpConditions: ZKPCondition[],
    merkleWitness: MerkleWitnessData,
    options: ZKPDeriveOptions,
  ): Promise<PresentedCredential>;
}

export function isZKPResolver(resolver: SchemaResolver): resolver is ZKPSchemaResolver {
  return 'deriveCredentialWithZKP' in resolver;
}

export function createZKPICAOSchemaResolver(
  zkpProvider?: ZKPProvider,
): ZKPSchemaResolver {
  const icaoResolver = createICAOSchemaResolver();

  return {
    type: 'ICAO9303SOD-ZKP',

    resolveField: icaoResolver.resolveField.bind(icaoResolver),

    deriveCredential: icaoResolver.deriveCredential.bind(icaoResolver),

    async deriveCredentialWithZKP(
      credential: MatchableCredential,
      discloseConditions: DiscloseCondition[],
      zkpConditions: ZKPCondition[],
      merkleWitness: MerkleWitnessData,
      options: ZKPDeriveOptions,
    ): Promise<PresentedCredential> {
      const proofs: CredentialProof[] = [];

      const subject: Record<string, unknown> = {};

      const provider = options.zkpProvider ?? zkpProvider;

      for (const cond of zkpConditions) {
        if (!provider) {
          throw new Error(`ZKPProvider required for condition "${cond.conditionID}"`);
        }

        const zkpProof = await buildZKPProof(cond, merkleWitness, provider);

        proofs.push(zkpProof);
      }

      const merkleConds = discloseConditions.filter((d) => d.merkleDisclosure);

      const nonMerkleConds = discloseConditions.filter((d) => !d.merkleDisclosure);

      if (merkleConds.length > 0) {
        const dg13Fields: Record<string, unknown> = {};

        for (const cond of merkleConds) {
          if (!isDg13Field(cond.field)) {
            throw new Error(
              `Field "${cond.field}" is not a DG13 field and cannot use Merkle disclosure`,
            );
          }

          const leafIndex = fieldIdToLeafIndex(cond.field);

          const fieldData = merkleWitness.fieldData[leafIndex];

          if (!fieldData) {
            throw new Error(`No field data at leaf index ${leafIndex} for "${cond.field}"`);
          }

          const siblings = extractSiblingsForLeaf(leafIndex, merkleWitness);

          const fieldValue = decodeFieldValue(fieldData.rawBytes);

          dg13Fields[cond.field] = fieldValue;

          const disclosure: MerkleDisclosureProof = {
            type: 'MerkleDisclosureProof',
            conditionID: cond.conditionID,
            fieldIndex: leafIndex,
            fieldValue,
            leafPreimage: {
              tagId: fieldData.tagId,
              length: fieldData.length,
              data: fieldData.packedFields,
              salt: merkleWitness.salt,
              packedHash: merkleWitness.packedHash,
            },
            siblings,
            commitment: merkleWitness.commitment,
            ...(cond.merkleDisclosure ? { dependsOn: { commitment: cond.merkleDisclosure.commitmentRef } } : {}),
          };

          proofs.push(disclosure);
        }

        subject.dg13 = dg13Fields;
      }

      if (nonMerkleConds.length > 0) {
        const hasMerkleDg13 = merkleConds.length > 0;

        const nonMerkleDg13Fields = nonMerkleConds.filter((d) => isDg13Field(d.field));

        if (hasMerkleDg13 && nonMerkleDg13Fields.length > 0) {
          throw new Error(
            `Cannot mix Merkle and non-Merkle disclosure for DG13 fields. ` +
            `Fields [${nonMerkleDg13Fields.map((d) => d.field).join(', ')}] must use merkleDisclosure ` +
            `when other DG13 fields use Merkle proofs.`,
          );
        }

        const nonMerkleFields = nonMerkleConds.map((d) => d.field);

        const baseCred = await icaoResolver.deriveCredential(
          credential,
          nonMerkleFields,
          { nonce: options.nonce },
        );

        for (const [key, val] of Object.entries(baseCred.credentialSubject)) {
          subject[key] = val;
        }

        if (baseCred.proof) {
          const existing = Array.isArray(baseCred.proof) ? baseCred.proof : [baseCred.proof];

          proofs.push(...existing);
        }
      }

      const types = [...(credential.type as readonly string[])];

      const issuer = typeof credential.issuer === 'string'
        ? credential.issuer
        : { ...credential.issuer };

      const presented: PresentedCredential = {
        type: types,
        issuer,
        credentialSubject: subject,
        proof: proofs,
      };

      if (credential['@context']) {
        presented['@context'] = [...(credential['@context'] as string[])];
      }

      if (credential.issuanceDate !== undefined) {
        presented.issuanceDate = credential.issuanceDate as string;
      }

      if (credential.id !== undefined) {
        presented.id = credential.id as string;
      }

      return presented;
    },
  };
}

async function buildZKPProof(
  condition: ZKPCondition,
  witness: MerkleWitnessData,
  provider: ZKPProvider,
): Promise<ZKPProof> {
  const result = await provider.prove({
    circuitId: condition.circuitId,
    privateInputs: {
      merkleWitness: witness,
    },
    publicInputs: {
      ...condition.publicInputs,
      salt: witness.salt,
      commitment: witness.commitment,
    },
  });

  return {
    type: 'ZKPProof',
    conditionID: condition.conditionID,
    circuitId: condition.circuitId,
    proofSystem: condition.proofSystem,
    publicInputs: {
      ...condition.publicInputs,
      salt: witness.salt,
      commitment: witness.commitment,
    },
    publicOutputs: result.publicOutputs,
    proofValue: result.proofValue,
    ...(condition.dependsOn ? { dependsOn: condition.dependsOn } : {}),
  };
}

function decodeFieldValue(rawBytes: number[]): string {
  return new TextDecoder().decode(new Uint8Array(rawBytes));
}
