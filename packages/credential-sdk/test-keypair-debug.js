const { Secp256k1Keypair } = require('./src/keypairs');
const { detectKeypairType, keypairToAddress } = require('./src/modules/ethr-did/utils');

// Create Secp256k1 keypair
const keypair = Secp256k1Keypair.random();

console.log('Constructor name:', keypair.constructor.name);
console.log('Has privateKey method:', typeof keypair.privateKey === 'function');
console.log('Detected type:', detectKeypairType(keypair));

try {
  const address = keypairToAddress(keypair);
  console.log('Address:', address);
} catch (e) {
  console.log('Error:', e.message);
  console.log('Stack:', e.stack);
}
