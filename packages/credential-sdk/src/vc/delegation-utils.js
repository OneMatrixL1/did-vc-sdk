import forge from 'node-forge';
import { base58btc } from 'multiformats/bases/base58';

/**
 * Verify a delegation certificate signed by the CCCD chip.
 * 
 * @param {object} certificate - Delegation certificate object
 * @param {string} certificate.holderDID - The holder's DID (did:ethr:...)
 * @param {string} certificate.chipDID - The chip's DID (did:key:z...) derived from DG15
 * @param {string} certificate.timestamp - ISO 8601 timestamp of the delegation
 * @param {string} certificate.aaSignature - The RSA signature from the chip (base64)
 * @returns {Promise<boolean>}
 */
export async function verifyDelegationCertificate(certificate) {
  const { holderDID, chipDID, timestamp, aaSignature } = certificate;

  if (!holderDID || !chipDID || !timestamp || !aaSignature) {
    throw new Error('Incomplete delegation certificate');
  }

  // 1. Verify Timestamp (Anti-replay & Expiration)
  // Handle both ISO strings and Unix seconds strings
  const certDate = /^\d+$/.test(timestamp)
    ? new Date(parseInt(timestamp) * 1000)
    : new Date(timestamp);

  const now = new Date();

  if (isNaN(certDate.getTime())) {
    console.error('❌ Delegation Error: Invalid timestamp format:', timestamp);
    throw new Error('Invalid timestamp in delegation certificate');
  }

  // Allow 15 min clock skew for future dates (be more generous for mobile/hardware)
  if (certDate > new Date(now.getTime() + 900000)) {
    console.error('❌ Delegation Error: Timestamp in future:', certDate.toISOString(), 'Now:', now.toISOString());
    throw new Error('Delegation certificate timestamp is in the future');
  }

  // Expire after 1 year
  const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
  if (now.getTime() - certDate.getTime() > ONE_YEAR_MS) {
    console.error('❌ Delegation Error: Expired:', certDate.toISOString());
    throw new Error('Delegation certificate has expired (max 1 year)');
  }

  // 2. Reconstruct Challenge (must match signer's logic exactly)
  // We use a fixed property order for deterministic JSON
  const payload = JSON.stringify({
    holderDID,
    chipDID,
    timestamp,
  });

  const md = forge.md.sha256.create();
  md.update(payload);
  const hashHex = md.digest().toHex();
  // We use 8 bytes (16 hex chars) for the AA challenge
  const recomputedChallenge = '0x' + hashHex.slice(0, 16);

  // 3. Extract RSA Public Key from chipDID
  const publicKey = await extractPublicKeyFromDid(chipDID);

  // 4. Verify RSA Signature
  const isValid = await verifyRSASignature(publicKey, recomputedChallenge, aaSignature);

  return isValid;
}

/**
 * Extracts the RSA public key from a did:key:z... DID.
 * @param {string} chipDID - The chip's DID (did:key:z...)
 * @returns {Promise<forge.pki.PublicKey>}
 */
async function extractPublicKeyFromDid(chipDID) {
  if (!chipDID.startsWith('did:key:z')) {
    throw new Error('Unsupported chipDID format. Only did:key:z (RSA) is supported.');
  }

  const multicodecKey = base58btc.decode(chipDID.split(':')[2]);

  // Multicodec prefix for rsa-pub is 0x1205 (encoded as varint [0x85, 0x24])
  if (multicodecKey[0] !== 0x85 || multicodecKey[1] !== 0x24) {
    throw new Error('Unsupported key type in did:key. Expected RSA.');
  }

  const spkiBytes = multicodecKey.slice(2);
  const spkiDer = forge.util.createBuffer(Buffer.from(spkiBytes));
  const publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(spkiDer));

  return publicKey;
}

/**
 * Verifies an RSA signature (Active Authentication typical format).
 * @param {forge.pki.PublicKey} publicKey 
 * @param {string} challenge - Hex string with 0x prefix
 * @param {string} signature - Base64 string
 */
async function verifyRSASignature(publicKey, challenge, signature) {
  const challengeHex = challenge.startsWith('0x') ? challenge.slice(2) : challenge;
  const challengeBytes = forge.util.hexToBytes(challengeHex);
  const signatureBytes = forge.util.decode64(signature);

  try {
    // 1. Try standard PKCS#1 v1.5 verification first
    const isValidPKCS = publicKey.verify(challengeBytes, signatureBytes, 'RSASSA-PKCS1-V1_5');
    if (isValidPKCS) {
      console.log('✅ PKCS#1 v1.5 verification success');
      return true;
    }
  } catch (err) {
    console.warn('⚠️ PKCS#1 v1.5 verification failed, trying raw RSA recovery (s^e mod n)');
  }

  try {
    // 2. Fallback: Raw public key operation (s^e mod n)
    // Recover the padded message and verify it using ISO/IEC 9796-2 or simple embedding.
    const n = publicKey.n;
    const e = publicKey.e;

    const sigBI = new forge.jsbn.BigInteger(forge.util.bytesToHex(signatureBytes), 16);
    const msgBI = sigBI.modPow(e, n);

    // Pad to modulus size in hex if necessary
    const nByteLen = Math.ceil(n.bitLength() / 8);
    const msgHex = msgBI.toString(16).padStart(nByteLen * 2, '0');
    const recoveredBytes = forge.util.hexToBytes(msgHex);

    // Case A: Simple embedding (challenge is part of M1)
    if (recoveredBytes.indexOf(challengeBytes) !== -1) {
      console.log('✅ Found challenge bytes in raw RSA block, verification success');
      return true;
    }

    // Case B: ISO/IEC 9796-2 Scheme 2 (Challenge is M2 - external message)
    // Format: 6A || M1 || Hash(M1 || M2) || BC
    if (recoveredBytes.length > 22 &&
      recoveredBytes.charCodeAt(0) === 0x6A &&
      recoveredBytes.charCodeAt(recoveredBytes.length - 1) === 0xBC) {
      console.log('📦 Detected ISO/IEC 9796-2 signature format, verifying hash...');

      // ICAO 9303 typically uses SHA-1 (20 bytes) for AA with RSA
      const hashLen = 20;
      const hashStart = recoveredBytes.length - 1 - hashLen;
      const embeddedHash = recoveredBytes.slice(hashStart, recoveredBytes.length - 1);
      const M1 = recoveredBytes.slice(1, hashStart);

      // Compute SHA-1(M1 || M2) where M2 is the challenge
      const md = forge.md.sha1.create();
      md.update(M1);
      md.update(challengeBytes);
      const recomputedHash = md.digest().toHex();
      const embeddedHashHex = forge.util.bytesToHex(embeddedHash);

      if (recomputedHash === embeddedHashHex) {
        console.log('✅ ISO/IEC 9796-2 (SHA-1) hash verification success');
        return true;
      } else {
        console.warn('❌ ISO/IEC 9796-2 (SHA-1) hash mismatch');
        console.warn('   Embedded:', embeddedHashHex);
        console.warn('   Recomputed:', recomputedHash);
      }

      // Try SHA-256 just in case (32 bytes)
      const hashLen256 = 32;
      if (recoveredBytes.length > hashLen256 + 2) {
        const hashStart256 = recoveredBytes.length - 1 - hashLen256;
        const embeddedHash256 = recoveredBytes.slice(hashStart256, recoveredBytes.length - 1);
        const M1_256 = recoveredBytes.slice(1, hashStart256);

        const md256 = forge.md.sha256.create();
        md256.update(M1_256);
        md256.update(challengeBytes);
        const recomputedHash256 = md256.digest().toHex();
        const embeddedHash256Hex = forge.util.bytesToHex(embeddedHash256);

        if (recomputedHash256 === embeddedHash256Hex) {
          console.log('✅ ISO/IEC 9796-2 (SHA-256) hash verification success');
          return true;
        }
      }
    }

    console.error('❌ Challenge verification failed in raw RSA block:', challengeHex);
    return false;
  } catch (e) {
    console.error('RSA signature verification failed during recovery:', e);
    return false;
  }
}
