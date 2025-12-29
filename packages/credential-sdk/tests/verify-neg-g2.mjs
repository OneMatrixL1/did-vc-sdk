/**
 * Verify the negated g2 values in the contract
 */
import { bls12_381 } from '@noble/curves/bls12-381';

// Dock g2 compressed
const dock_g2_compressed_hex = '951113a09ccd914117226445cd4d5aa6d82218d8d3f5b517d7b43020c94ee0121642129e969b3e14c41b737823f65dcf02445bd9067ed201f4b93771091e40c8920deb706ce68690b02eb80ebddc6c7b5001e5087170d04b70e2fb85b8f5fd51';
const dock_g2 = bls12_381.G2.ProjectivePoint.fromHex(Buffer.from(dock_g2_compressed_hex, 'hex'));

// Get negated g2
const neg_dock_g2 = dock_g2.negate();

// Output uncompressed
const neg_g2_bytes = neg_dock_g2.toRawBytes(false);
console.log('Negated g2 uncompressed (192 bytes):');
console.log(Buffer.from(neg_g2_bytes).toString('hex'));

// Break into parts
const x1 = neg_g2_bytes.slice(0, 48);
const x0 = neg_g2_bytes.slice(48, 96);
const y1 = neg_g2_bytes.slice(96, 144);
const y0 = neg_g2_bytes.slice(144, 192);

console.log('\n=== Solidity Constants (copy-paste) ===');

// x1
const x1_hi = x1.slice(0, 16);
const x1_lo = x1.slice(16, 48);
console.log(`uint128 private constant N_G2_X1_HI = 0x${Buffer.from(x1_hi).toString('hex')};`);
console.log(`uint256 private constant N_G2_X1_LO = 0x${Buffer.from(x1_lo).toString('hex')};`);

// x0
const x0_hi = x0.slice(0, 16);
const x0_lo = x0.slice(16, 48);
console.log(`uint128 private constant N_G2_X0_HI = 0x${Buffer.from(x0_hi).toString('hex')};`);
console.log(`uint256 private constant N_G2_X0_LO = 0x${Buffer.from(x0_lo).toString('hex')};`);

// y1
const y1_hi = y1.slice(0, 16);
const y1_lo = y1.slice(16, 48);
console.log(`uint128 private constant N_G2_Y1_HI = 0x${Buffer.from(y1_hi).toString('hex')};`);
console.log(`uint256 private constant N_G2_Y1_LO = 0x${Buffer.from(y1_lo).toString('hex')};`);

// y0
const y0_hi = y0.slice(0, 16);
const y0_lo = y0.slice(16, 48);
console.log(`uint128 private constant N_G2_Y0_HI = 0x${Buffer.from(y0_hi).toString('hex')};`);
console.log(`uint256 private constant N_G2_Y0_LO = 0x${Buffer.from(y0_lo).toString('hex')};`);

// Compare with current contract values
console.log('\n=== Contract Current Values ===');
console.log('N_G2_X1_HI: 0x151113a09ccd914117226445cd4d5aa6');
console.log('N_G2_X1_LO: 0xd82218d8d3f5b517d7b43020c94ee0121642129e969b3e14c41b737823f65dcf');
console.log('N_G2_X0_HI: 0x02445bd9067ed201f4b93771091e40c8');
console.log('N_G2_X0_LO: 0x920deb706ce68690b02eb80ebddc6c7b5001e5087170d04b70e2fb85b8f5fd51');
console.log('N_G2_Y1_HI: 0x0dd7275196d32fba62ba5d15c45aaa87');
console.log('N_G2_Y1_LO: 0x494aa7bab4fa7e5c9f903739c83c410a19d8b22e12a777fedc6f4552c75a0ddc');
console.log('N_G2_Y0_HI: 0x0c71cc5492173d4d92a5ee851c15cdc1');
console.log('N_G2_Y0_LO: 0x71269f0ac4cd0a371205341e5ccc4367f69d1609fa0dc1ffaca9cbbee6580f95');
