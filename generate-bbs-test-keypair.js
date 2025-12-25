#!/usr/bin/env node
/**
 * Generate a BBS keypair with compressed and uncompressed G2 public keys
 * for contract testing
 */

const { BBSKeypair, BBSSignatureParams, BBS_SIGNATURE_PARAMS_LABEL_BYTES } = require('@docknetwork/crypto-wasm-ts');
const { bls12_381: bls } = require('@noble/curves/bls12-381');
const { keccak_256 } = require('@noble/hashes/sha3');

async function generateTestKeypair() {
  // Generate BBS keypair (default msgCount=1)
  const sigParams = BBSSignatureParams.getSigParamsOfRequiredSize(1, BBS_SIGNATURE_PARAMS_LABEL_BYTES);
  const bbsKeypair = BBSKeypair.generate(sigParams);

  // Get compressed G2 public key (96 bytes - BBS standard)
  const publicKeyCompressed = bbsKeypair.pk.value;

  // Expand to uncompressed G2 (192 bytes) using @noble/curves
  const point = bls.G2.ProjectivePoint.fromHex(publicKeyCompressed);
  const publicKeyUncompressed = point.toRawBytes(false);

  // Derive Ethereum address from UNCOMPRESSED key
  const hash = keccak_256(publicKeyUncompressed);
  const address = '0x' + Buffer.from(hash.slice(-20)).toString('hex');

  console.log('=== BBS Keypair for Contract Testing ===\n');

  console.log('COMPRESSED (96 bytes - BBS standard):');
  console.log('  Length:', publicKeyCompressed.length, 'bytes');
  console.log('  Hex:', '0x' + Buffer.from(publicKeyCompressed).toString('hex'));
  console.log('  Base64:', Buffer.from(publicKeyCompressed).toString('base64'));

  console.log('\nUNCOMPRESSED (192 bytes - Contract input):');
  console.log('  Length:', publicKeyUncompressed.length, 'bytes');
  console.log('  Hex:', '0x' + Buffer.from(publicKeyUncompressed).toString('hex'));
  console.log('  Base64:', Buffer.from(publicKeyUncompressed).toString('base64'));

  console.log('\nDERIVED ADDRESS:');
  console.log('  ', address);

  console.log('\n=== SOLIDITY TEST DATA ===\n');

  console.log('// For your Solidity tests:');
  console.log('bytes memory publicKeyCompressed = 0x' + Buffer.from(publicKeyCompressed).toString('hex') + ';');
  console.log('bytes memory publicKeyUncompressed = 0x' + Buffer.from(publicKeyUncompressed).toString('hex') + ';');
  console.log('address expectedAddress = ' + address + ';');

  console.log('\n=== VERIFICATION ===');
  console.log('Your contract should be able to:');
  console.log('1. Take publicKeyCompressed (96 bytes) as input');
  console.log('2. Expand it to 192 bytes');
  console.log('3. Derive the same address:', address);
}

// Initialize WASM if needed
require('@docknetwork/crypto-wasm-ts').initializeWasm()
  .then(() => generateTestKeypair())
  .catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
  });
