/**
 * Bundled circuit artifacts — compiled with nargo v1.0.0-beta.12 + bb v0.87.0.
 *
 * Each circuit has:
 *   - bytecode JSON (Noir compiled) for proving via noir.execute + backend.generateProof
 *   - verification key (binary) for verifying via backend.verifyProof
 *
 * The provider loads these from the bundled circuits/ directory at runtime.
 * No network downloads needed.
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname_resolved = typeof __dirname !== 'undefined'
  ? __dirname
  : dirname(fileURLToPath(import.meta.url));

const CIRCUITS_DIR = join(__dirname_resolved, '..', 'circuits');

export interface CircuitArtifact {
  bytecode: string;
  abi: unknown;
}

const CIRCUIT_FILE_MAP: Record<string, string> = {
  'sod-validate': 'sod_validate_circuit',
  'dg13-merklelize': 'dg13_merklelize_circuit',
  'date-greaterthan': 'date_greaterthan_predicate_circuit',
  'date-lessthan': 'date_lessthan_predicate_circuit',
  'date-greaterthanorequal': 'date_greaterthanorequal_predicate_circuit',
  'date-lessthanorequal': 'date_lessthanorequal_predicate_circuit',
  'date-inrange': 'date_inrange_predicate_circuit',
};

export function getAvailableCircuits(): string[] {
  return Object.keys(CIRCUIT_FILE_MAP);
}

export function loadCircuit(circuitId: string): CircuitArtifact {
  const baseName = CIRCUIT_FILE_MAP[circuitId];
  if (!baseName) {
    throw new Error(`Unknown circuitId "${circuitId}". Available: [${Object.keys(CIRCUIT_FILE_MAP).join(', ')}]`);
  }
  const jsonPath = join(CIRCUITS_DIR, `${baseName}.json`);
  if (!existsSync(jsonPath)) {
    throw new Error(`Circuit artifact not found: ${jsonPath}`);
  }
  return JSON.parse(readFileSync(jsonPath, 'utf-8')) as CircuitArtifact;
}

export function loadVerificationKey(circuitId: string): Uint8Array {
  const baseName = CIRCUIT_FILE_MAP[circuitId];
  if (!baseName) {
    throw new Error(`Unknown circuitId "${circuitId}"`);
  }
  const vkPath = join(CIRCUITS_DIR, `${baseName}.vk`);
  if (!existsSync(vkPath)) {
    throw new Error(`Verification key not found: ${vkPath}`);
  }
  return new Uint8Array(readFileSync(vkPath));
}
