/**
 * Debug full contract call parameters
 */
import { ethers } from 'ethers';
import { bls12_381 } from '@noble/curves/bls12-381';
import dock from '@docknetwork/crypto-wasm-ts';
const { initializeWasm, SignatureParamsG1 } = dock;
// Use compiled dist version
import Bls12381BBSKeyPairDock2023 from '../dist/esm/vc/crypto/Bls12381BBSKeyPairDock2023.js';

async function main() {
  await initializeWasm();

  // Generate BBS keypair
  const bbsKeypair = Bls12381BBSKeyPairDock2023.generate();

  // Get private and public key
  const privateKeyBuffer = bbsKeypair.privateKeyBuffer.value
    ? new Uint8Array(bbsKeypair.privateKeyBuffer.value)
    : new Uint8Array(bbsKeypair.privateKeyBuffer);
  const publicKeyBuffer = bbsKeypair.publicKeyBuffer.value
    ? new Uint8Array(bbsKeypair.publicKeyBuffer.value)
    : new Uint8Array(bbsKeypair.publicKeyBuffer);

  console.log('=== BBS Keypair ===');
  console.log('Private key (32 bytes):', Buffer.from(privateKeyBuffer).toString('hex'));
  console.log('Public key compressed (96 bytes):', Buffer.from(publicKeyBuffer).toString('hex'));

  // Decompress public key to 192 bytes
  const pubkeyPoint = bls12_381.G2.ProjectivePoint.fromHex(publicKeyBuffer);
  const uncompressedPubkey = pubkeyPoint.toRawBytes(false);
  console.log('Public key uncompressed (192 bytes):', Buffer.from(uncompressedPubkey).toString('hex'));

  // Derive Ethereum address from uncompressed pubkey
  const pubkeyHash = ethers.keccak256(uncompressedPubkey);
  const address = ethers.getAddress('0x' + pubkeyHash.slice(-40));
  console.log('Derived address (identity):', address);

  // New owner (random)
  const newOwner = '0x9BE1C43625fd81F157277CfA81bBD710e3610175';

  // EIP-712 domain separator (from contract deployment)
  // Contract uses: keccak256(abi.encode(TYPE_HASH, keccak256(bytes(NAME)), keccak256(bytes(VERSION)), block.chainid, address(this)))
  const NAME = 'EthereumDIDRegistry';
  const VERSION = '1';
  const TYPE_HASH = ethers.keccak256(ethers.toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
  const chainId = 84005; // VietChain
  const contractAddress = '0x8697547b3b82327B70A90C6248662EC083ad5A62';

  const abiCoder = new ethers.AbiCoder();
  const DOMAIN_SEPARATOR = ethers.keccak256(
    abiCoder.encode(
      ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
      [TYPE_HASH, ethers.keccak256(ethers.toUtf8Bytes(NAME)), ethers.keccak256(ethers.toUtf8Bytes(VERSION)), chainId, contractAddress]
    )
  );
  console.log('\n=== EIP-712 ===');
  console.log('DOMAIN_SEPARATOR:', DOMAIN_SEPARATOR);

  // Struct hash
  const CHANGE_OWNER_WITH_PUBKEY_TYPEHASH = ethers.keccak256(
    ethers.toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)')
  );
  console.log('CHANGE_OWNER_WITH_PUBKEY_TYPEHASH:', CHANGE_OWNER_WITH_PUBKEY_TYPEHASH);

  const structHash = ethers.keccak256(
    abiCoder.encode(
      ['bytes32', 'address', 'address', 'address'],
      [CHANGE_OWNER_WITH_PUBKEY_TYPEHASH, address, address, newOwner]
    )
  );
  console.log('structHash:', structHash);

  // Final EIP-712 hash (contract: keccak256(abi.encodePacked(EIP191_HEADER, DOMAIN_SEPARATOR, structHash)))
  const EIP191_HEADER = '0x1901';
  const hash = ethers.keccak256(
    ethers.concat([EIP191_HEADER, DOMAIN_SEPARATOR, structHash])
  );
  console.log('EIP-712 hash:', hash);

  // Hash message to G1 point
  const hashBytes = ethers.getBytes(hash);
  const DST = 'BLS_DST';
  const messagePoint = bls12_381.G1.hashToCurve(hashBytes, { DST });
  const messageBytes = messagePoint.toRawBytes(false);
  console.log('\n=== Hash to Point G1 ===');
  console.log('message G1 (96 bytes):', Buffer.from(messageBytes).toString('hex'));

  // Sign: signature = sk * H(message)
  // BBS private key is little-endian, need to reverse for Noble
  const reversed = new Uint8Array(privateKeyBuffer).reverse();
  const privateKeyScalar = bls12_381.fields.Fr.create(BigInt('0x' + Buffer.from(reversed).toString('hex')));

  const signaturePoint = messagePoint.multiply(privateKeyScalar);
  const signatureBytes = signaturePoint.toRawBytes(false);
  console.log('\n=== Signature ===');
  console.log('signature G1 (96 bytes):', Buffer.from(signatureBytes).toString('hex'));

  // Load Dock's g2 generator (from previous test output)
  const dock_g2_compressed_hex = '951113a09ccd914117226445cd4d5aa6d82218d8d3f5b517d7b43020c94ee0121642129e969b3e14c41b737823f65dcf02445bd9067ed201f4b93771091e40c8920deb706ce68690b02eb80ebddc6c7b5001e5087170d04b70e2fb85b8f5fd51';
  const dock_g2_bytes = Buffer.from(dock_g2_compressed_hex, 'hex');
  const dock_g2 = bls12_381.G2.ProjectivePoint.fromHex(dock_g2_bytes);

  console.log('\n=== Dock G2 ===');
  console.log('Dock g2 compressed:', dock_g2_compressed_hex);
  console.log('Dock g2 uncompressed:', Buffer.from(dock_g2.toRawBytes(false)).toString('hex'));

  // Verification: e(sig, g2) = e(message, pk)
  // Contract does: e(sig, -g2) * e(message, pk) = 1
  const negG2 = dock_g2.negate();

  // Compute pairings
  const pairing1 = bls12_381.pairing(signaturePoint, negG2);
  const pairing2 = bls12_381.pairing(messagePoint, pubkeyPoint);

  // Multiply pairings
  const product = bls12_381.fields.Fp12.mul(pairing1, pairing2);

  // Check if product equals 1 (identity)
  const isValid = bls12_381.fields.Fp12.eql(product, bls12_381.fields.Fp12.ONE);

  console.log('\n=== Local Verification ===');
  console.log('Pairing verification result:', isValid);

  // Also try alternative verification: e(sig, g2) = e(message, pk)
  const p1 = bls12_381.pairing(signaturePoint, dock_g2);
  const p2 = bls12_381.pairing(messagePoint, pubkeyPoint);
  const isValid2 = bls12_381.fields.Fp12.eql(p1, p2);
  console.log('Alternative pairing check (e(sig,g2)=e(m,pk)):', isValid2);

  // Print contract call parameters
  console.log('\n=== Contract Call Parameters ===');
  console.log('identity:', address);
  console.log('newOwner:', newOwner);
  console.log('publicKey (192 bytes):', Buffer.from(uncompressedPubkey).toString('hex'));
  console.log('signature (96 bytes):', Buffer.from(signatureBytes).toString('hex'));
}

main().catch(console.error);
