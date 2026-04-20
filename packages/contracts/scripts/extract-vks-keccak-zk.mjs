#!/usr/bin/env node
/**
 * Regenerate backend `vks.ts` under UltraKeccakZK flavor using @aztec/bb.js.
 *
 * Loads each circuit artifact, calls `UltraHonkBackend.getSolidityVerifier`
 * with `{ verifierTarget: 'evm' }` (Keccak + ZK), parses the G1Point constants
 * out of the generated Solidity, then emits the backend's `vks.ts` shape.
 *
 * Run from `packages/did-vc-sdk/packages/contracts` with the workspace deps
 * hoisted:
 *    node scripts/extract-vks-keccak-zk.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..', '..');
const CIRCUITS_DIR = resolve(REPO_ROOT, 'did-circuits/circuits');
const VKS_TS_PATH = resolve(
  REPO_ROOT,
  'events-backend/apps/api/src/modules/registry/vks.ts',
);

const CIRCUITS = [
  { jsName: 'sodValidate', file: 'sod_validate_circuit.json' },
  { jsName: 'dgBridge', file: 'dg_bridge_circuit.json' },
  { jsName: 'uniqueIdentity', file: 'unique_identity_circuit.json' },
];

const FIELD_ORDER = [
  'circuitSize', 'logCircuitSize', 'publicInputsSize',
  'qm', 'qc', 'ql', 'qr', 'qo', 'q4',
  'qLookup', 'qArith', 'qDeltaRange', 'qMemory', 'qNnf', 'qElliptic',
  'qPoseidon2External', 'qPoseidon2Internal',
  's1', 's2', 's3', 's4',
  'id1', 'id2', 'id3', 'id4',
  't1', 't2', 't3', 't4',
  'lagrangeFirst', 'lagrangeLast',
];

const POINT_RE = /(\w+):\s*Honk\.G1Point\(\{\s*x:\s*uint256\((0x[0-9a-fA-F]+)\),\s*y:\s*uint256\((0x[0-9a-fA-F]+)\)\s*\}\)/g;
const VK_HASH_RE = /uint256\s+constant\s+VK_HASH\s*=\s*(0x[0-9a-fA-F]+)/;
const SIZE_RE = /circuitSize:\s*uint256\((\d+)\),[\s\S]*?logCircuitSize:\s*uint256\((\d+)\),[\s\S]*?publicInputsSize:\s*uint256\((\d+)\)/;

function parseRefSol(solText) {
  const hashM = VK_HASH_RE.exec(solText);
  if (!hashM) throw new Error('VK_HASH not found');
  const sizeM = SIZE_RE.exec(solText);
  if (!sizeM) throw new Error('size fields not found');

  const vkStart = solText.indexOf('Honk.VerificationKey memory vk = Honk.VerificationKey({');
  const vkEnd = solText.indexOf('});', vkStart);
  const vkBody = solText.slice(vkStart, vkEnd);

  const points = {};
  let m;
  POINT_RE.lastIndex = 0;
  while ((m = POINT_RE.exec(vkBody))) {
    points[m[1]] = { x: m[2], y: m[3] };
  }

  return {
    vkHash: hashM[1],
    circuitSize: BigInt(sizeM[1]),
    logCircuitSize: BigInt(sizeM[2]),
    publicInputsSize: BigInt(sizeM[3]),
    points,
  };
}

function formatVk(parsed) {
  const lines = ['{'];
  lines.push(`  circuitSize: ${parsed.circuitSize}n,`);
  lines.push(`  logCircuitSize: ${parsed.logCircuitSize}n,`);
  lines.push(`  publicInputsSize: ${parsed.publicInputsSize}n,`);
  for (const field of FIELD_ORDER) {
    if (field === 'circuitSize' || field === 'logCircuitSize' || field === 'publicInputsSize') continue;
    const p = parsed.points[field];
    if (!p) throw new Error(`Missing G1Point ${field}`);
    lines.push(`  ${field}: { x: "${p.x}", y: "${p.y}" },`);
  }
  lines.push('}');
  return lines.join('\n');
}

async function main() {
  const bb = await import('@aztec/bb.js');
  const { Barretenberg, UltraHonkBackend } = bb;
  const api = await Barretenberg.new();

  const results = [];
  for (const circuit of CIRCUITS) {
    console.log(`\n=== ${circuit.file} ===`);
    const artifact = JSON.parse(
      readFileSync(resolve(CIRCUITS_DIR, circuit.file), 'utf8'),
    );
    const backend = new UltraHonkBackend(artifact.bytecode, api);
    const vk = await backend.getVerificationKey({ verifierTarget: 'evm' });
    console.log(`  vk bytes: ${vk.length}`);
    const sol = await backend.getSolidityVerifier(vk, { verifierTarget: 'evm' });
    const parsed = parseRefSol(sol);
    console.log(`  vkHash = ${parsed.vkHash}`);
    console.log(`  circuitSize = ${parsed.circuitSize}, logCircuitSize = ${parsed.logCircuitSize}, publicInputsSize = ${parsed.publicInputsSize}`);
    results.push({ ...circuit, parsed });
  }

  const header = `// Auto-generated under UltraKeccakZK flavor by packages/contracts/scripts/extract-vks-keccak-zk.mjs.
// Do not edit by hand. Re-run after any circuit rebuild.

`;
  const body = results.map((r) =>
    `export const ${r.jsName}Vk = ${formatVk(r.parsed)};\n\nexport const ${r.jsName}VkHash = "${r.parsed.vkHash}";\n`,
  ).join('\n');

  writeFileSync(VKS_TS_PATH, header + body);
  console.log(`\nWrote ${VKS_TS_PATH}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
