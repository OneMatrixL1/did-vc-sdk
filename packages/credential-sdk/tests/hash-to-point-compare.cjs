/**
 * Compare hash-to-point results between Noble and contract
 */
const { bls12_381 } = require('@noble/curves/bls12-381');

// Simple message for testing
const message = Buffer.from('test message');
const DST = 'BLS_DST';

// Hash to G1 using Noble
const point = bls12_381.G1.hashToCurve(message, { DST });
const uncompressed = point.toRawBytes(false); // 96 bytes

console.log('Message:', message.toString('hex'));
console.log('DST:', DST);
console.log('G1 point (uncompressed 96 bytes):');
console.log(Buffer.from(uncompressed).toString('hex'));

// Also test with EIP-712 hash format
const { ethers } = require('ethers');

const identity = '0x4bB592f87eAD0AA6ded5F2dc9F7F94Aa3dbA73e8';
const oldOwner = identity;
const newOwner = '0x9BE1C43625fd81F157277CfA81bBD710e3610175';

// Replicate EIP-712 hash construction from contract
const CHANGE_OWNER_WITH_PUBKEY_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)')
);

// DOMAIN_SEPARATOR from contract (need to calculate)
// We'll use a simple test case
const abiCoder = new ethers.AbiCoder();
const structHash = ethers.keccak256(
  abiCoder.encode(
    ['bytes32', 'address', 'address', 'address'],
    [CHANGE_OWNER_WITH_PUBKEY_TYPEHASH, identity, oldOwner, newOwner]
  )
);

console.log('\n=== EIP-712 Test ===');
console.log('structHash:', structHash);

// The contract does: keccak256(abi.encodePacked(hash)) where hash is already 32 bytes
// Actually looking at line 655, it does: abi.encodePacked(hash)
// abi.encodePacked of bytes32 is just the bytes32 itself
const hashBytes = ethers.getBytes(structHash);
console.log('hashBytes:', Buffer.from(hashBytes).toString('hex'));

const messagePoint = bls12_381.G1.hashToCurve(hashBytes, { DST });
const messageUncompressed = messagePoint.toRawBytes(false);

console.log('G1 message point (uncompressed):');
console.log(Buffer.from(messageUncompressed).toString('hex'));

// Break it down into the format contract expects (x_hi, x_lo, y_hi, y_lo)
const x = messageUncompressed.slice(0, 48);
const y = messageUncompressed.slice(48, 96);

console.log('\nG1 point breakdown:');
console.log('x (48 bytes):', Buffer.from(x).toString('hex'));
console.log('y (48 bytes):', Buffer.from(y).toString('hex'));

// Contract expects:
// x_hi (16 bytes) | x_lo (32 bytes)
// y_hi (16 bytes) | y_lo (32 bytes)
const x_hi = x.slice(0, 16);
const x_lo = x.slice(16, 48);
const y_hi = y.slice(0, 16);
const y_lo = y.slice(16, 48);

console.log('\nContract format:');
console.log('x_hi:', Buffer.from(x_hi).toString('hex'));
console.log('x_lo:', Buffer.from(x_lo).toString('hex'));
console.log('y_hi:', Buffer.from(y_hi).toString('hex'));
console.log('y_lo:', Buffer.from(y_lo).toString('hex'));
