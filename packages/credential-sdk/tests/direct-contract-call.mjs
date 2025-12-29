/**
 * Direct contract call test - bypasses SDK to test contract directly
 */
import { ethers } from 'ethers';
import { bls12_381 } from '@noble/curves/bls12-381';
import dock from '@docknetwork/crypto-wasm-ts';
const { initializeWasm } = dock;
import Bls12381BBSKeyPairDock2023 from '../dist/esm/vc/crypto/Bls12381BBSKeyPairDock2023.js';

// Contract ABI (only what we need)
const ABI = [
  'function changeOwnerWithPubkey(address identity, address oldOwner, address newOwner, bytes calldata publicKey, bytes calldata signature) external',
  'function identityOwner(address identity) external view returns (address)',
  'function DOMAIN_SEPARATOR() external view returns (bytes32)',
];

const REGISTRY_ADDRESS = '0x8697547b3b82327B70A90C6248662EC083ad5A62';
const RPC_URL = 'https://rpc.vietcha.in';
const PRIVATE_KEY = '0xb88b9077de440ba0d0848ce95ccc130498b722955618673bcb1773689e77032a';

async function main() {
  await initializeWasm();

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  const contract = new ethers.Contract(REGISTRY_ADDRESS, ABI, wallet);

  // Get DOMAIN_SEPARATOR from contract
  const contractDomainSeparator = await contract.DOMAIN_SEPARATOR();
  console.log('Contract DOMAIN_SEPARATOR:', contractDomainSeparator);

  // Generate BBS keypair
  const bbsKeypair = Bls12381BBSKeyPairDock2023.generate();

  // Get private and public key
  const privateKeyBuffer = bbsKeypair.privateKeyBuffer.value
    ? new Uint8Array(bbsKeypair.privateKeyBuffer.value)
    : new Uint8Array(bbsKeypair.privateKeyBuffer);
  const publicKeyBuffer = bbsKeypair.publicKeyBuffer.value
    ? new Uint8Array(bbsKeypair.publicKeyBuffer.value)
    : new Uint8Array(bbsKeypair.publicKeyBuffer);

  // Decompress public key to 192 bytes
  const pubkeyPoint = bls12_381.G2.ProjectivePoint.fromHex(publicKeyBuffer);
  const uncompressedPubkey = pubkeyPoint.toRawBytes(false);

  // Derive identity address
  const pubkeyHash = ethers.keccak256(uncompressedPubkey);
  const identity = ethers.getAddress('0x' + pubkeyHash.slice(-40));
  console.log('Identity:', identity);

  // New owner
  const newOwner = '0x9BE1C43625fd81F157277CfA81bBD710e3610175';
  console.log('New Owner:', newOwner);

  // Check current owner
  const currentOwner = await contract.identityOwner(identity);
  console.log('Current Owner (from contract):', currentOwner);
  console.log('Should be same as identity (default):', currentOwner === identity);

  // Compute EIP-712 hash using the same method as SDK
  const chainId = 84005;
  const abiCoder = new ethers.AbiCoder();

  const CHANGE_OWNER_WITH_PUBKEY_TYPEHASH = ethers.keccak256(
    ethers.toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)')
  );

  const structHash = ethers.keccak256(
    abiCoder.encode(
      ['bytes32', 'address', 'address', 'address'],
      [CHANGE_OWNER_WITH_PUBKEY_TYPEHASH, identity, identity, newOwner]
    )
  );

  const hash = ethers.keccak256(
    ethers.concat(['0x1901', contractDomainSeparator, structHash])
  );
  console.log('EIP-712 hash:', hash);

  // Sign
  const hashBytes = ethers.getBytes(hash);
  const DST = 'BLS_DST';
  const messagePoint = bls12_381.G1.hashToCurve(hashBytes, { DST });

  // BBS private key to scalar
  const reversed = new Uint8Array(privateKeyBuffer).reverse();
  const privateKeyScalar = bls12_381.fields.Fr.create(BigInt('0x' + Buffer.from(reversed).toString('hex')));

  const signaturePoint = messagePoint.multiply(privateKeyScalar);
  const signatureBytes = signaturePoint.toRawBytes(false);

  console.log('\n=== Calling Contract ===');
  console.log('publicKey length:', uncompressedPubkey.length);
  console.log('signature length:', signatureBytes.length);

  // Local verification first
  const dock_g2_compressed_hex = '951113a09ccd914117226445cd4d5aa6d82218d8d3f5b517d7b43020c94ee0121642129e969b3e14c41b737823f65dcf02445bd9067ed201f4b93771091e40c8920deb706ce68690b02eb80ebddc6c7b5001e5087170d04b70e2fb85b8f5fd51';
  const dock_g2 = bls12_381.G2.ProjectivePoint.fromHex(Buffer.from(dock_g2_compressed_hex, 'hex'));

  const p1 = bls12_381.pairing(signaturePoint, dock_g2);
  const p2 = bls12_381.pairing(messagePoint, pubkeyPoint);
  const isValidLocal = bls12_381.fields.Fp12.eql(p1, p2);
  console.log('Local verification:', isValidLocal);

  if (!isValidLocal) {
    console.log('Local verification failed! Aborting contract call.');
    return;
  }

  try {
    // Call the contract (with oldOwner = identity since it's the default owner)
    const oldOwner = identity;
    const tx = await contract.changeOwnerWithPubkey(
      identity,
      oldOwner,
      newOwner,
      uncompressedPubkey,
      signatureBytes,
      { gasLimit: 500000 }
    );
    console.log('TX hash:', tx.hash);
    const receipt = await tx.wait();
    console.log('Receipt:', receipt.status === 1 ? 'SUCCESS' : 'FAILED');
  } catch (error) {
    console.log('Error:', error.message);
    if (error.data) {
      console.log('Error data:', error.data);
    }
  }
}

main().catch(console.error);
