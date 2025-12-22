/**
 * Pure BLS12-381 Keypair for Ethereum smart contract BLS verification.
 *
 * This keypair uses standard BLS12-381 derivation:
 * - Secret key: 32-byte scalar
 * - Public key: G2 = G2_BASE * secretKey (96 bytes compressed, 192 bytes uncompressed)
 * - Signature: G1 = hashToG1(message) * secretKey (96 bytes uncompressed)
 *
 * This is different from BBS keypairs which use additional parameters in derivation.
 * Use this class for BLS signatures that will be verified by Ethereum smart contracts.
 *
 * @module keypairs/keypair-bls12381
 */

import { ethers } from 'ethers';

let bls12_381Module = null;

async function getBls12381() {
    if (!bls12_381Module) {
        const module = await import('@noble/curves/bls12-381');

        bls12_381Module = module.bls12_381;
    }

    return bls12_381Module;
}

/**
 * Pure BLS12-381 keypair for smart contract BLS verification.
 */
export default class Bls12381Keypair {
    /**
     * Private constructor - use static factory methods instead.
     * @param {Uint8Array} secretKey - 32-byte secret key
     * @param {Uint8Array} publicKeyCompressed - 96-byte compressed G2 public key
     * @param {Uint8Array} publicKeyUncompressed - 192-byte uncompressed G2 public key
     */
    constructor(secretKey, publicKeyCompressed, publicKeyUncompressed) {
        this.secretKey = secretKey;

        this.publicKeyCompressed = publicKeyCompressed;

        this.publicKeyUncompressed = publicKeyUncompressed;
    }

    /**
     * Generate a random BLS12-381 keypair.
     * @returns {Promise<Bls12381Keypair>} New keypair
     */
    static async generate() {
        const bls = await getBls12381();

        const secretKey = bls.utils.randomPrivateKey();

        return Bls12381Keypair.fromSecretKey(secretKey);
    }

    /**
     * Create keypair from a 32-byte secret key.
     * @param {Uint8Array|Array<number>} secretKeyBytes - 32-byte secret key
     * @returns {Promise<Bls12381Keypair>} Keypair
     */
    static async fromSecretKey(secretKeyBytes) {
        const bls = await getBls12381();

        const secretKey = secretKeyBytes instanceof Uint8Array
            ? secretKeyBytes
            : new Uint8Array(secretKeyBytes);

        if (secretKey.length !== 32) {
            throw new Error('Secret key must be 32 bytes');
        }

        // Derive G2 public key manually: pk = G2_BASE * sk
        // This ensures mathematical consistency with our manual signing below
        const skScalar = bls.fields.Fr.fromBytes(secretKey);
        const g2Point = bls.G2.ProjectivePoint.BASE.multiply(skScalar);

        const publicKeyCompressed = g2Point.toRawBytes(true);
        const publicKeyUncompressed = g2Point.toRawBytes(false);

        return new Bls12381Keypair(secretKey, publicKeyCompressed, publicKeyUncompressed);
    }

    /**
     * Create keypair from hex-encoded secret key.
     * @param {string} secretKeyHex - 0x-prefixed or raw hex secret key
     * @returns {Promise<Bls12381Keypair>} Keypair
     */
    static async fromSecretKeyHex(secretKeyHex) {
        const hex = secretKeyHex.startsWith('0x') ? secretKeyHex.slice(2) : secretKeyHex;
        const secretKey = new Uint8Array(Buffer.from(hex, 'hex'));

        return Bls12381Keypair.fromSecretKey(secretKey);
    }

    /**
     * Get Ethereum address derived from public key (uncompressed).
     * Address = last 20 bytes of keccak256(publicKeyUncompressed)
     * @returns {string} Checksummed Ethereum address
     */
    get address() {
        const hash = ethers.utils.keccak256(this.publicKeyUncompressed);

        return ethers.utils.getAddress(`0x${hash.slice(-40)}`);
    }

    /**
     * Get public key as 0x-prefixed hex string (uncompressed, 192 bytes).
     * This is the format expected by smart contracts.
     * @returns {string} 0x-prefixed hex string (386 characters)
     */
    get publicKeyHex() {
        const hex = Array.from(this.publicKeyUncompressed)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');

        return `0x${hex}`;
    }

    /**
     * Sign a message using BLS12-381 Short Signature scheme (G1 signature).
     *
     * @param {Uint8Array} messageBytes - Payload to sign (raw bytes)
     * @param {string|Uint8Array} dstBytes - Domain Separation Tag (required)
     * @returns {Promise<Uint8Array>} 96-byte uncompressed G1 signature
     */
    async signBLS(messageBytes, dstBytes) {
        const bls = await getBls12381();

        const dst = typeof dstBytes === 'string'
            ? new TextEncoder().encode(dstBytes)
            : new Uint8Array(dstBytes);

        const message = messageBytes instanceof Uint8Array
            ? messageBytes
            : new Uint8Array(messageBytes);

        // Manual Hash-to-Curve G1 with custom DST
        const messagePoint = bls.G1.hashToCurve(message, { DST: dst });

        // Manual Sign: signature = messagePoint * secretKey
        const skScalar = bls.fields.Fr.fromBytes(this.secretKey);
        const signaturePoint = messagePoint.multiply(skScalar);

        // Return uncompressed G1 (96 bytes)
        return signaturePoint.toRawBytes(false);
    }

    /**
     * Convert signature bytes to hex string.
     * @param {Uint8Array} signatureBytes - Signature bytes
     * @returns {string} 0x-prefixed hex string
     */
    static signatureToHex(signatureBytes) {
        const hex = Array.from(signatureBytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');

        return `0x${hex}`;
    }
}
