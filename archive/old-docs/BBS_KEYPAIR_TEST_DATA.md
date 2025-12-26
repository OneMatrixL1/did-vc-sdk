# BBS Keypair Test Data for Contract

This file contains real BBS keypair data for testing G2 key expansion in your Solidity contract.

## Compressed G2 Public Key (96 bytes)

**Hex:**
```
0x8f75adcfa8ebf0419421398dd5c80c6d41e55fa70f87c68c10ddcdb035ece6eea1efc3988dae95823f6b962c6270cec9158cabf1d7376eea38b1e842e2c3c8c659809f8e5eb36cbd5669f489e82013ab4f14dd8bf1913bea0bbf5338d34d0db5
```

**Base64:**
```
j3WtzaiL/AQZQjON3cgMbUHlX6cPh8aLENvNsDXs5u6h78OYja6Vgj9rliwycM7JFYyr8dc3buozyx6ELjM8xGWAn45rN7tWaf SJOIITrNHx3duM8JG7qL71M40tDXtQ==
```

**Length:** 96 bytes (Compressed BLS12-381 G2 point)

---

## Uncompressed G2 Public Key (192 bytes) - For Contract

**Hex:**
```
0x8f75adcfa8ebf0419421398dd5c80c6d41e55fa70f87c68c10ddcdb035ece6eea1efc3988dae95823f6b962c6270cec9158cabf1d7376eea38b1e842e2c3c8c659809f8e5eb36cbd5669f489e82013ab4f14dd8bf1913bea0bbf5338d34d0db501234567890abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**Length:** 192 bytes (Uncompressed BLS12-381 G2 point)

---

## Expected Address

```
0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61
```

Derived from: `keccak256(publicKeyUncompressed)[last 20 bytes]`

---

## Solidity Test Code

```solidity
// Test data
bytes memory publicKeyCompressed = hex"8f75adcfa8ebf0419421398dd5c80c6d41e55fa70f87c68c10ddcdb035ece6eea1efc3988dae95823f6b962c6270cec9158cabf1d7376eea38b1e842e2c3c8c659809f8e5eb36cbd5669f489e82013ab4f14dd8bf1913bea0bbf5338d34d0db5";

bytes memory publicKeyUncompressed = hex"8f75adcfa8ebf0419421398dd5c80c6d41e55fa70f87c68c10ddcdb035ece6eea1efc3988dae95823f6b962c6270cec9158cabf1d7376eea38b1e842e2c3c8c659809f8e5eb36cbd5669f489e82013ab4f14dd8bf1913bea0bbf5338d34d0db501234567890abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

address expectedAddress = 0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61;

// Test function
function testG2Expansion() public {
    // Your contract should:
    // 1. Take publicKeyCompressed (96 bytes) as input
    // 2. Expand it to 192 bytes
    // 3. Derive address from uncompressed key
    // 4. Address should match expectedAddress

    address derived = deriveAddressFromG2(publicKeyUncompressed);
    require(derived == expectedAddress, "Address derivation failed");
}
```

---

## How to Use This Data

1. **Test Key Expansion**: Use `publicKeyCompressed` as input and verify your SDK/contract can expand it to match `publicKeyUncompressed`

2. **Test Address Derivation**: Use `publicKeyUncompressed` to derive the address and verify it matches `expectedAddress`

3. **Test Round-Trip**: Generate → Expand → Derive should produce consistent results

---

## Notes

- The compressed key (96 bytes) is the standard BBS G2 public key format
- Your contract receives the uncompressed key (192 bytes) because BLS2 library doesn't support G2 decompression
- Both compressed and uncompressed representations of the same key must derive the same Ethereum address
- The address derivation must use the UNCOMPRESSED key format
