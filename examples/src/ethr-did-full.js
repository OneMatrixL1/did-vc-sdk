/**
 * Comprehensive example of ethr DID management
 * Demonstrates:
 * - Creating ethr DIDs on different networks
 * - Updating DID documents
 * - Signing Verifiable Credentials with ethr DIDs
 * - Creating Verifiable Presentations with ethr DIDs
 * - Multi-network configuration
 */

import { EthrDIDModule, createVietChainConfig } from '@docknetwork/credential-sdk/modules/ethr-did';
import { Secp256k1Keypair, DidKeypair } from '@docknetwork/credential-sdk/keypairs';
import {
  VerifiableCredential,
  VerifiablePresentation,
  issueCredential,
  signPresentation,
} from '@docknetwork/credential-sdk/vc';
import { EcdsaSecp256k1Signature2019 } from '@docknetwork/credential-sdk/vc/crypto';

/**
 * Example 1: Create ethr DID on VietChain
 */
async function example1_createDIDOnVietChain() {
  console.log('\n=== Example 1: Create DID on VietChain ===');

  // Configure module for VietChain
  const module = new EthrDIDModule({
    networks: [createVietChainConfig()],
    defaultNetwork: 'vietchain',
  });

  // Generate new keypair
  const keypair = Secp256k1Keypair.random();

  // Create DID (no on-chain transaction needed for basic DID)
  const did = await module.createNewDID(keypair);
  console.log('Created DID on VietChain:', did);

  // Resolve the DID document
  const document = await module.getDocument(did);
  console.log('DID Document:', JSON.stringify(document, null, 2));

  return { module, keypair, did };
}

/**
 * Example 2: Create DID with multiple networks
 */
async function example2_multiNetworkSetup() {
  console.log('\n=== Example 2: Multi-Network Setup ===');

  // Configure module with multiple networks
  const module = new EthrDIDModule({
    networks: [
      'mainnet', // Use default config
      'sepolia', // Use default config
      createVietChainConfig(), // Custom network
    ],
    defaultNetwork: 'vietchain',
  });

  const keypair = Secp256k1Keypair.random();

  // Create DIDs on different networks
  const vietChainDID = await module.createNewDID(keypair, 'vietchain');
  console.log('VietChain DID:', vietChainDID);

  const sepoliaDID = await module.createNewDID(keypair, 'sepolia');
  console.log('Sepolia DID:', sepoliaDID);

  const mainnetDID = await module.createNewDID(keypair, 'mainnet');
  console.log('Mainnet DID:', mainnetDID);

  return { module, keypair, did: vietChainDID };
}

/**
 * Example 3: Add attributes to DID (requires on-chain transaction)
 */
async function example3_addAttributes(module, keypair, did) {
  console.log('\n=== Example 3: Add Attributes to DID ===');

  try {
    // Add a service endpoint attribute
    console.log('Adding service endpoint attribute...');
    const receipt = await module.setAttribute(
      did,
      'did/svc/MessagingService',
      'https://example.com/messaging',
      keypair,
    );
    console.log('Attribute added! Transaction hash:', receipt.transactionHash);

    // Add a public key attribute
    console.log('Adding public key attribute...');
    const keyReceipt = await module.setAttribute(
      did,
      'did/pub/Secp256k1/veriKey',
      keypair.publicKeyHex,
      keypair,
    );
    console.log('Public key added! Transaction hash:', keyReceipt.transactionHash);

    // Resolve updated document
    const updatedDoc = await module.getDocument(did);
    console.log('Updated DID Document:', JSON.stringify(updatedDoc, null, 2));
  } catch (error) {
    console.log('Note: Attribute updates require network access and gas fees');
    console.log('Error:', error.message);
  }
}

/**
 * Example 4: Add and revoke delegates
 */
async function example4_manageDelegates(module, keypair, did) {
  console.log('\n=== Example 4: Manage Delegates ===');

  try {
    // Create a delegate keypair
    const delegateKeypair = Secp256k1Keypair.random();
    const delegateAddress = delegateKeypair.publicKeyHex;

    console.log('Adding delegate...');
    const addReceipt = await module.addDelegate(
      did,
      delegateAddress,
      keypair,
      {
        delegateType: 'veriKey',
        expiresIn: 86400, // 1 day
      },
    );
    console.log('Delegate added! Transaction hash:', addReceipt.transactionHash);

    // Revoke the delegate
    console.log('Revoking delegate...');
    const revokeReceipt = await module.revokeDelegate(
      did,
      delegateAddress,
      keypair,
      'veriKey',
    );
    console.log('Delegate revoked! Transaction hash:', revokeReceipt.transactionHash);
  } catch (error) {
    console.log('Note: Delegate management requires network access and gas fees');
    console.log('Error:', error.message);
  }
}

/**
 * Example 5: Sign Verifiable Credential with ethr DID
 */
async function example5_signCredential(did, keypair) {
  console.log('\n=== Example 5: Sign Verifiable Credential ===');

  // Create a credential
  const credential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1',
    ],
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: did,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
      degree: {
        type: 'BachelorDegree',
        name: 'Bachelor of Science and Arts',
      },
    },
  };

  // Create key document for signing
  const keyDoc = {
    id: `${did}#controller`,
    controller: did,
    type: 'EcdsaSecp256k1VerificationKey2019',
    privateKeyHex: Array.from(keypair.privateKey())
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
    publicKeyHex: Array.from(keypair.publicKey())
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
  };

  // Sign the credential
  const signedCredential = await issueCredential(keyDoc, credential);
  console.log('Signed Credential:', JSON.stringify(signedCredential, null, 2));

  return signedCredential;
}

/**
 * Example 6: Create and sign Verifiable Presentation
 */
async function example6_createPresentation(did, keypair, credential) {
  console.log('\n=== Example 6: Create Verifiable Presentation ===');

  // Create presentation
  const presentation = new VerifiablePresentation('http://example.edu/credentials/presentation/456');
  presentation.addCredential(credential);
  presentation.setHolder(did);

  // Create key document for signing
  const keyDoc = {
    id: `${did}#controller`,
    controller: did,
    type: 'EcdsaSecp256k1VerificationKey2019',
    privateKeyHex: Array.from(keypair.privateKey())
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
    publicKeyHex: Array.from(keypair.publicKey())
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
  };

  // Sign the presentation
  const signedPresentation = await signPresentation(
    presentation.toJSON(),
    keyDoc,
    'challenge-123',
    'example.com',
  );

  console.log('Signed Presentation:', JSON.stringify(signedPresentation, null, 2));

  return signedPresentation;
}

/**
 * Example 7: Change DID owner
 */
async function example7_changeOwner(module, keypair, did) {
  console.log('\n=== Example 7: Change DID Owner ===');

  try {
    // Create new owner keypair
    const newOwnerKeypair = Secp256k1Keypair.random();
    const newOwnerAddress = `0x${Array.from(newOwnerKeypair.publicKey().slice(-20))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')}`;

    console.log('Changing owner to:', newOwnerAddress);
    const receipt = await module.changeOwner(did, newOwnerAddress, keypair);
    console.log('Owner changed! Transaction hash:', receipt.transactionHash);

    console.log('Note: After changing owner, only the new owner can update the DID');
  } catch (error) {
    console.log('Note: Changing owner requires network access and gas fees');
    console.log('Error:', error.message);
  }
}

/**
 * Main function - runs all examples
 */
async function main() {
  console.log('=== Ethr DID Management - Comprehensive Example ===');
  console.log('This example demonstrates all features of the EthrDIDModule');

  try {
    // Example 1: Create DID on VietChain
    const { module, keypair, did } = await example1_createDIDOnVietChain();

    // Example 2: Multi-network setup
    await example2_multiNetworkSetup();

    // Example 3: Add attributes (requires network access)
    // Uncomment if you have network access and gas fees covered:
    // await example3_addAttributes(module, keypair, did);

    // Example 4: Manage delegates (requires network access)
    // Uncomment if you have network access and gas fees covered:
    // await example4_manageDelegates(module, keypair, did);

    // Example 5: Sign credential
    const credential = await example5_signCredential(did, keypair);

    // Example 6: Create presentation
    await example6_createPresentation(did, keypair, credential);

    // Example 7: Change owner (requires network access)
    // Uncomment if you have network access and gas fees covered:
    // await example7_changeOwner(module, keypair, did);

    console.log('\n=== All Examples Completed Successfully ===');
    console.log('\nNote: Examples 3, 4, and 7 are commented out because they require:');
    console.log('  1. Network connectivity to VietChain');
    console.log('  2. Gas fees (native tokens) in your account');
    console.log('  3. The DID registry contract to be deployed');
    console.log('\nTo enable these examples, ensure you have the requirements and uncomment them.');
  } catch (error) {
    console.error('Error in examples:', error);
    throw error;
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main()
    .then(() => {
      console.log('\nExamples completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\nError occurred:', error);
      process.exit(1);
    });
}

export default main;
