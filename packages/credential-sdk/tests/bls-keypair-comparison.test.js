/**
 * Unit test to analyze why BBS and Noble produce different public keys
 */

import { bls12_381 } from '@noble/curves/bls12-381';
import { ethers } from 'ethers';
import { initializeWasm, BBSSignatureParams, BBS_SIGNATURE_PARAMS_LABEL_BYTES } from '@docknetwork/crypto-wasm-ts';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';

describe('BLS Keypair Analysis: BBS vs Noble', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('analyzes how private key is interpreted differently', async () => {
    // Generate BBS keypair
    const bbsKeypair = Bls12381BBSKeyPairDock2023.generate();

    // Extract private key bytes
    let privateKeyBytes = bbsKeypair.privateKeyBuffer;
    if (privateKeyBytes && privateKeyBytes.value) {
      privateKeyBytes = new Uint8Array(privateKeyBytes.value);
    } else if (!(privateKeyBytes instanceof Uint8Array)) {
      privateKeyBytes = new Uint8Array(privateKeyBytes);
    }

    // Get BBS public key
    let bbsPublicKey = bbsKeypair.publicKeyBuffer;
    if (bbsPublicKey && bbsPublicKey.value) {
      bbsPublicKey = new Uint8Array(bbsPublicKey.value);
    } else if (!(bbsPublicKey instanceof Uint8Array)) {
      bbsPublicKey = new Uint8Array(bbsPublicKey);
    }

    console.log('\n=== Private Key Analysis ===');
    console.log('Private key (hex, as-is):', ethers.hexlify(privateKeyBytes));
    console.log('Private key length:', privateKeyBytes.length, 'bytes');

    // Try different interpretations with Noble:

    // Method 1: normPrivateKeyToScalar (standard BLS way)
    const scalar1 = bls12_381.G2.normPrivateKeyToScalar(privateKeyBytes);
    const pubkey1 = bls12_381.G2.ProjectivePoint.BASE.multiply(scalar1).toRawBytes(false);

    // Method 2: Reverse bytes (little-endian vs big-endian)
    const reversedBytes = new Uint8Array(privateKeyBytes).reverse();
    const scalar2 = bls12_381.G2.normPrivateKeyToScalar(reversedBytes);
    const pubkey2 = bls12_381.G2.ProjectivePoint.BASE.multiply(scalar2).toRawBytes(false);

    // Method 3: Try as raw scalar (no hashing/normalization)
    // Noble's Fr field for scalar
    let scalar3;
    try {
      // Direct interpretation as big-endian integer mod r
      const Fr = bls12_381.fields.Fr;
      scalar3 = Fr.create(BigInt('0x' + Buffer.from(privateKeyBytes).toString('hex')));
      const pubkey3 = bls12_381.G2.ProjectivePoint.BASE.multiply(scalar3).toRawBytes(false);
      console.log('\nMethod 3 (raw scalar BE):', ethers.hexlify(pubkey3).slice(0, 66) + '...');
    } catch (e) {
      console.log('\nMethod 3 failed:', e.message);
    }

    // Method 4: Little-endian raw scalar
    try {
      const Fr = bls12_381.fields.Fr;
      scalar3 = Fr.create(BigInt('0x' + Buffer.from(reversedBytes).toString('hex')));
      const pubkey4 = bls12_381.G2.ProjectivePoint.BASE.multiply(scalar3).toRawBytes(false);
      console.log('Method 4 (raw scalar LE):', ethers.hexlify(pubkey4).slice(0, 66) + '...');
    } catch (e) {
      console.log('Method 4 failed:', e.message);
    }

    console.log('\n=== Public Key Comparison ===');
    console.log('BBS pubkey (compressed):', ethers.hexlify(bbsPublicKey));
    console.log('Noble method 1 (normPrivateKeyToScalar):', ethers.hexlify(pubkey1).slice(0, 66) + '...');
    console.log('Noble method 2 (reversed bytes):', ethers.hexlify(pubkey2).slice(0, 66) + '...');

    // Decompress BBS pubkey to compare
    const bbsUncompressed = bls12_381.G2.ProjectivePoint.fromHex(bbsPublicKey).toRawBytes(false);
    console.log('\nBBS pubkey (uncompressed):', ethers.hexlify(bbsUncompressed).slice(0, 66) + '...');

    // Check which method matches
    const method1Match = ethers.hexlify(pubkey1) === ethers.hexlify(bbsUncompressed);
    const method2Match = ethers.hexlify(pubkey2) === ethers.hexlify(bbsUncompressed);

    console.log('\n=== Match Results ===');
    console.log('Method 1 (normPrivateKeyToScalar) matches BBS:', method1Match);
    console.log('Method 2 (reversed bytes) matches BBS:', method2Match);

    // Check the G2 generator used by Noble
    const nobleG2Base = bls12_381.G2.ProjectivePoint.BASE.toRawBytes(false);
    console.log('\n=== Generator Analysis ===');
    console.log('Noble G2 BASE (first 64 hex):', ethers.hexlify(nobleG2Base).slice(0, 66) + '...');

    // Check what generator BBS uses from signature params
    const bbsParams = BBSSignatureParams.generate(1, BBS_SIGNATURE_PARAMS_LABEL_BYTES);
    console.log('BBS params keys:', Object.keys(bbsParams));
    console.log('BBS params value keys:', bbsParams.value ? Object.keys(bbsParams.value) : 'no value');
    console.log('BBS params:', JSON.stringify(bbsParams, (k, v) =>
      v instanceof Uint8Array ? `Uint8Array(${v.length})` : v, 2).slice(0, 500));

    // Try multiplying private key by BBS g2 generator from params.value.g2
    if (bbsParams.value && bbsParams.value.g2) {
      try {
        const bbsG2Bytes = new Uint8Array(bbsParams.value.g2);
        console.log('BBS g2 length:', bbsG2Bytes.length);
        console.log('BBS g2 (hex):', ethers.hexlify(bbsG2Bytes).slice(0, 66) + '...');

        const bbsG2Point = bls12_381.G2.ProjectivePoint.fromHex(bbsG2Bytes);
        console.log('BBS g2 decoded OK');

        // Try: pubkey = sk * bbsG2 with different scalar interpretations
        const Fr = bls12_381.fields.Fr;

        // Big-endian interpretation
        const skBE = Fr.create(BigInt('0x' + Buffer.from(privateKeyBytes).toString('hex')));
        const pubkeyBE = bbsG2Point.multiply(skBE).toRawBytes(false);
        console.log('sk(BE) * BBS_g2:', ethers.hexlify(pubkeyBE).slice(0, 66) + '...');

        // Little-endian interpretation
        const skLE = Fr.create(BigInt('0x' + Buffer.from(reversedBytes).toString('hex')));
        const pubkeyLE = bbsG2Point.multiply(skLE).toRawBytes(false);
        console.log('sk(LE) * BBS_g2:', ethers.hexlify(pubkeyLE).slice(0, 66) + '...');

        const matchBE = ethers.hexlify(pubkeyBE) === ethers.hexlify(bbsUncompressed);
        const matchLE = ethers.hexlify(pubkeyLE) === ethers.hexlify(bbsUncompressed);
        console.log('sk(BE) * BBS_g2 matches BBS pubkey:', matchBE);
        console.log('sk(LE) * BBS_g2 matches BBS pubkey:', matchLE);
      } catch (e) {
        console.log('Error with BBS g2:', e.message);
      }
    }

    console.log('=== END ===\n');
  });

  it('verifies BBS keypair signing matches public key with Dock g2', async () => {
    // Generate BBS keypair
    const bbsKeypair = Bls12381BBSKeyPairDock2023.generate();

    // Extract private key (little-endian in BBS)
    let privateKeyBytes = bbsKeypair.privateKeyBuffer;
    if (privateKeyBytes && privateKeyBytes.value) {
      privateKeyBytes = new Uint8Array(privateKeyBytes.value);
    }

    // Get BBS public key
    let bbsPublicKey = bbsKeypair.publicKeyBuffer;
    if (bbsPublicKey && bbsPublicKey.value) {
      bbsPublicKey = new Uint8Array(bbsPublicKey.value);
    } else if (!(bbsPublicKey instanceof Uint8Array)) {
      bbsPublicKey = new Uint8Array(bbsPublicKey);
    }

    // Get Dock g2 generator
    const bbsParams = BBSSignatureParams.generate(1, BBS_SIGNATURE_PARAMS_LABEL_BYTES);
    const dockG2 = bls12_381.G2.ProjectivePoint.fromHex(new Uint8Array(bbsParams.value.g2));

    // Convert private key to scalar (BBS uses little-endian)
    const reversedKey = new Uint8Array(privateKeyBytes).reverse();
    const Fr = bls12_381.fields.Fr;
    const privateKeyScalar = Fr.create(BigInt('0x' + Buffer.from(reversedKey).toString('hex')));

    // Verify: BBS pubkey = sk * Dock_g2
    const derivedPubkey = dockG2.multiply(privateKeyScalar).toRawBytes(false);
    const bbsPubUncompressed = bls12_381.G2.ProjectivePoint.fromHex(bbsPublicKey).toRawBytes(false);

    console.log('\n=== Verify BBS signing matches pubkey ===');
    console.log('BBS pubkey:', ethers.hexlify(bbsPubUncompressed).slice(0, 50) + '...');
    console.log('sk * Dock_g2:', ethers.hexlify(derivedPubkey).slice(0, 50) + '...');
    console.log('Match:', ethers.hexlify(derivedPubkey) === ethers.hexlify(bbsPubUncompressed));

    // Sign a test message
    const testMessage = new Uint8Array([1, 2, 3, 4, 5]);
    const DST = 'BLS_DST';
    const messagePoint = bls12_381.G1.hashToCurve(testMessage, { DST });
    const signaturePoint = messagePoint.multiply(privateKeyScalar);
    const signature = signaturePoint.toRawBytes(false);

    // Verify signature using pairing with Dock g2
    // e(sig, Dock_g2) == e(H(m), pk)
    const sigPoint = bls12_381.G1.ProjectivePoint.fromHex(signature);
    const pubPoint = bls12_381.G2.ProjectivePoint.fromHex(bbsPubUncompressed);
    const msgPoint = bls12_381.G1.hashToCurve(testMessage, { DST });

    const pairing1 = bls12_381.pairing(sigPoint, dockG2);
    const pairing2 = bls12_381.pairing(msgPoint, pubPoint);
    const verified = bls12_381.fields.Fp12.eql(pairing1, pairing2);

    console.log('Signature verified with Dock g2:', verified);
    console.log('=== END ===\n');

    expect(ethers.hexlify(derivedPubkey) === ethers.hexlify(bbsPubUncompressed)).toBe(true);
    expect(verified).toBe(true);
  });

  it('outputs Dock BBS g2 generator for contract', async () => {
    // Generate params with Dock's default label
    const bbsParams = BBSSignatureParams.generate(1, BBS_SIGNATURE_PARAMS_LABEL_BYTES);
    const paramsG2Compressed = new Uint8Array(bbsParams.value.g2);

    // Decompress to 192 bytes for contract
    const paramsG2Point = bls12_381.G2.ProjectivePoint.fromHex(paramsG2Compressed);
    const paramsG2Uncompressed = paramsG2Point.toRawBytes(false);

    // Negate the point for pairing (contract uses -G2)
    const negatedPoint = paramsG2Point.negate();
    const negatedG2 = negatedPoint.toRawBytes(false);

    console.log('\n=== Dock BBS g2 Generator for Contract ===');
    console.log('Label:', 'DockBBSSignature2023');
    console.log('');
    console.log('g2 compressed (96 bytes):');
    console.log(ethers.hexlify(paramsG2Compressed));
    console.log('');
    console.log('g2 uncompressed (192 bytes):');
    console.log(ethers.hexlify(paramsG2Uncompressed));
    console.log('');
    console.log('-g2 (negated, for contract pairing):');
    console.log(ethers.hexlify(negatedG2));
    console.log('');

    // Noble's G2 serialization is: x.c1 (48) | x.c0 (48) | y.c1 (48) | y.c0 (48)
    // Contract order is: X0, X1, Y0, Y1
    // So we need to swap: noble[0:48]=x1, noble[48:96]=x0, noble[96:144]=y1, noble[144:192]=y0
    const hex = ethers.hexlify(negatedG2).slice(2); // remove 0x

    // Each coordinate is 48 bytes = 96 hex chars
    // Noble order: x1, x0, y1, y0
    const x1 = hex.slice(0, 96);
    const x0 = hex.slice(96, 192);
    const y1 = hex.slice(192, 288);
    const y0 = hex.slice(288, 384);

    // Contract expects: X0, X1, Y0, Y1
    console.log('=== Solidity Constants (for BLS2.sol) ===');
    console.log('// Dock BBS g2 generator (negated) from label "DockBBSSignature2023"');
    console.log(`uint128 private constant N_G2_X0_HI = 0x${x0.slice(0, 32)};`);
    console.log(`uint256 private constant N_G2_X0_LO = 0x${x0.slice(32, 96)};`);
    console.log(`uint128 private constant N_G2_X1_HI = 0x${x1.slice(0, 32)};`);
    console.log(`uint256 private constant N_G2_X1_LO = 0x${x1.slice(32, 96)};`);
    console.log(`uint128 private constant N_G2_Y0_HI = 0x${y0.slice(0, 32)};`);
    console.log(`uint256 private constant N_G2_Y0_LO = 0x${y0.slice(32, 96)};`);
    console.log(`uint128 private constant N_G2_Y1_HI = 0x${y1.slice(0, 32)};`);
    console.log(`uint256 private constant N_G2_Y1_LO = 0x${y1.slice(32, 96)};`);
    console.log('=== END ===\n');
  });

  it('shows BBS keypair has TWO different public keys', async () => {
    // Generate BBS keypair
    const bbsKeypair = Bls12381BBSKeyPairDock2023.generate();

    // Extract private key
    let privateKeyBytes = bbsKeypair.privateKeyBuffer;
    if (privateKeyBytes && privateKeyBytes.value) {
      privateKeyBytes = new Uint8Array(privateKeyBytes.value);
    } else if (!(privateKeyBytes instanceof Uint8Array)) {
      privateKeyBytes = new Uint8Array(privateKeyBytes);
    }

    // Get BBS public key (from the library)
    let bbsPublicKey = bbsKeypair.publicKeyBuffer;
    if (bbsPublicKey && bbsPublicKey.value) {
      bbsPublicKey = new Uint8Array(bbsPublicKey.value);
    } else if (!(bbsPublicKey instanceof Uint8Array)) {
      bbsPublicKey = new Uint8Array(bbsPublicKey);
    }
    const bbsPublicKeyUncompressed = bls12_381.G2.ProjectivePoint.fromHex(bbsPublicKey).toRawBytes(false);

    // Derive Noble public key (reversed bytes + G2.BASE)
    const privateKeyBE = new Uint8Array(privateKeyBytes).reverse();
    const Fr = bls12_381.fields.Fr;
    const scalar = Fr.create(BigInt('0x' + Buffer.from(privateKeyBE).toString('hex')));
    const noblePublicKey = bls12_381.G2.ProjectivePoint.BASE.multiply(scalar).toRawBytes(false);

    // Derive addresses
    const bbsAddress = ethers.getAddress(
      ethers.hexlify(ethers.getBytes(ethers.keccak256(bbsPublicKeyUncompressed)).slice(-20))
    );
    const nobleAddress = ethers.getAddress(
      ethers.hexlify(ethers.getBytes(ethers.keccak256(noblePublicKey)).slice(-20))
    );

    console.log('\n=== Same Private Key, TWO Different Public Keys ===');
    console.log('Private key:', ethers.hexlify(privateKeyBytes));
    console.log('');
    console.log('BBS public key:', ethers.hexlify(bbsPublicKeyUncompressed).slice(0, 66) + '...');
    console.log('BBS address:', bbsAddress);
    console.log('');
    console.log('Noble public key:', ethers.hexlify(noblePublicKey).slice(0, 66) + '...');
    console.log('Noble address:', nobleAddress);
    console.log('');
    console.log('Same public key?', ethers.hexlify(bbsPublicKeyUncompressed) === ethers.hexlify(noblePublicKey));
    console.log('Same address?', bbsAddress === nobleAddress);
    console.log('=== END ===\n');

    // They should be DIFFERENT
    expect(bbsAddress).not.toBe(nobleAddress);
  });

  it('converts BBS private key to Noble-compatible keypair', async () => {
    // Generate BBS keypair
    const bbsKeypair = Bls12381BBSKeyPairDock2023.generate();

    // Extract private key bytes
    let privateKeyBytes = bbsKeypair.privateKeyBuffer;
    if (privateKeyBytes && privateKeyBytes.value) {
      privateKeyBytes = new Uint8Array(privateKeyBytes.value);
    } else if (!(privateKeyBytes instanceof Uint8Array)) {
      privateKeyBytes = new Uint8Array(privateKeyBytes);
    }

    console.log('\n=== BBS to Noble Conversion ===');
    console.log('BBS private key (LE):', ethers.hexlify(privateKeyBytes));

    // Step 1: Reverse bytes (LE → BE)
    const privateKeyBE = new Uint8Array(privateKeyBytes).reverse();
    console.log('Private key (BE):', ethers.hexlify(privateKeyBE));

    // Step 2: Use Noble's standard G2.BASE to derive public key
    const Fr = bls12_381.fields.Fr;
    const scalar = Fr.create(BigInt('0x' + Buffer.from(privateKeyBE).toString('hex')));
    const noblePublicKey = bls12_381.G2.ProjectivePoint.BASE.multiply(scalar).toRawBytes(false);
    console.log('Noble public key (G2.BASE):', ethers.hexlify(noblePublicKey).slice(0, 66) + '...');

    // Step 3: Derive address from Noble public key
    const nobleAddress = ethers.getAddress(
      ethers.hexlify(ethers.getBytes(ethers.keccak256(noblePublicKey)).slice(-20))
    );
    console.log('Noble-derived address:', nobleAddress);

    // Step 4: Sign a test message
    const testMessage = new Uint8Array([1, 2, 3, 4, 5]);
    const DST = 'BLS_DST';
    const messagePoint = bls12_381.G1.hashToCurve(testMessage, { DST });
    const signaturePoint = messagePoint.multiply(scalar);
    const signature = signaturePoint.toRawBytes(false);
    console.log('Signature (G1):', ethers.hexlify(signature).slice(0, 66) + '...');

    // Step 5: Verify signature
    const G2Generator = bls12_381.G2.ProjectivePoint.BASE;
    const sigPoint = bls12_381.G1.ProjectivePoint.fromHex(signature);
    const pubPoint = bls12_381.G2.ProjectivePoint.fromHex(noblePublicKey);
    const msgPoint = bls12_381.G1.hashToCurve(testMessage, { DST });

    const pairing1 = bls12_381.pairing(sigPoint, G2Generator);
    const pairing2 = bls12_381.pairing(msgPoint, pubPoint);
    const verified = bls12_381.fields.Fp12.eql(pairing1, pairing2);

    console.log('Signature verified:', verified);
    console.log('=== END ===\n');

    expect(verified).toBe(true);
  });
});
