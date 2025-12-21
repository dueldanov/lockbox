# LockBox Requirements - Appendices

## 10. Appendices

### 10.1 LockScript Grammar

#### 10.1.1 Syntax Rules

- Scripts consist of `secure_operation` blocks within `secure_context`
- Case-sensitive identifiers and keywords
- Single-line comments with `//`
- Whitespace ignored except in string literals

#### 10.1.2 Keywords and Constructs

| Keyword | Purpose |
|---------|---------|
| `secure_operation` | Defines a function with inputs and outputs |
| `secure_context` | Wraps operations with automatic memory clearing |
| `if, else` | Conditional branching |
| `for` | Iteration over arrays or ranges |
| `return` | Returns value, clears sensitive locals |
| `throw` | Raises structured error |

#### 10.1.3 Data Types

**Primitive Types:**
- `int`, `float`, `Bool`, `String`

**Security-Focused Types:**
- `SecureString`, `SecureChar`, `SecureShard`
- `ZKPProof`, `BundleID`, `TransactionID`, `SecureData`

#### 10.1.4 Example Operation

```lockscript
secure_operation store_key(key: SecureString) -> BundleID {
    validate_length(key, max: 256)
    real_chars = to_char_array(key)
    decoys = create_decoys(real_chars, ratio: get_tier_ratio())
    shards = split_key(key, decoys)
    tx_ids = assign_shards(shards, tier: get_current_tier())
    bundle_id = generate_bundle_id()
    secure_context {
        log_operation("store", true)
    }
    return bundle_id
}
```

---

### 10.2 Error Codes

#### 10.2.1 Core Error Codes

| Code | Message |
|------|---------|
| `SHARD_UNAVAILABLE` | Shard retrieval failed |
| `ACCESS_DENIED` | Authentication failed |
| `PROOF_INVALID` | ZKP validation failed |
| `TOKEN_INVALID` | Token invalid or expired |
| `INSUFFICIENT_REGIONS` | Fewer than 3 regions available |
| `USERNAME_TAKEN` | Username already registered |
| `INSUFFICIENT_SHARD_MATCHES` | Fewer shards decrypted than expected |
| `NETWORK_PARTITIONED` | Network experiencing partition |
| `TIER_VIOLATION` | Operation not permitted for user's tier |
| `BUNDLE_NOT_FOUND` | Requested bundle ID doesn't exist |
| `METADATA_CORRUPT` | Metadata cannot be processed |
| `RATE_LIMITED` | Too many requests in time period |

#### 10.2.2 Error Severity Levels

| Severity | Description |
|----------|-------------|
| `CRITICAL` | Operation failed, cannot proceed |
| `WARNING` | Operation succeeded but with issues |
| `INFO` | Informational message about operation |

---

### 10.3 Security Enhancements

#### 10.3.1 Purpose-Specific HKDF

- Enhanced info parameter with domain, purpose, and index
- Salt addition: Unique purpose-specific salt for key derivation
- Memory management: Enhanced secure wiping for all byte slices

#### 10.3.2 Metadata Optimization

- Reduced footprint with only essential fields
- Ephemeral ZKPs: Store hashes only, wipe full proofs
- Transaction bundle salt: Unique 32-byte random salt per bundle

#### 10.3.3 Alerting

- Encryption alerting: Triggered on character shard encryption failures
- Admin notifications: For critical node count and network issues

---

## 11. Software Hash Verification System for LockSmith Nodes

> **Note:** This requirement is only done after we have completed the code, tested and ready to go into production.

### Node Integrity Verification

The LockBox system implements a robust node integrity verification system to ensure only authentic, unmodified LockSmith node software participates in the private key storage network, while keeping token transactions accessible through standard blockchain protocols.

### Node-to-Node Verification

- All LockSmith nodes verify each other's software integrity during connection establishment using SHA-256 cryptographic hashes
- During initial connection handshake, nodes exchange software version information and binary hashes
- Nodes validate received hashes against official signed hashes for corresponding versions
- Connections are only established between nodes with matching verified hashes
- Periodic re-verification occurs during ongoing operation to ensure continued integrity
- Failed verification results in connection termination with "INVALID_SOFTWARE_VERSION" error

### Hash Generation and Distribution

- Official release process generates cryptographic hash (SHA-256) of LockSmith binaries
- LockBox signs this hash with its private key to create verifiable signed hashes
- Signed hashes are distributed to all LockBox-operated nodes through the secure internal update management system
- Hash verification uses standard cryptographic libraries with tamper-resistant implementations
- The verification process validates the entire binary, not just selected portions

### Dual-Party Verification

- Each official LockSmith software release is verified and signed by two parties:
  1. LockBox administration (primary signature)
  2. An independent security audit firm (secondary signature)
- Both signatures are required for node software to be considered valid
- This dual-signature approach prevents a single compromised entity from approving malicious software
- The verification process includes comprehensive security audit before signing
- The identity of the security firm is publicly disclosed to enhance transparency

### Software Update Mechanism

- New software versions add their hashes to the approved list via the dual-signature process
- Older versions can be deprecated by removing their hashes from the approved list
- Nodes regularly check for hash list updates through the internal update system
- Update mechanism includes version transition periods to prevent network disruption

### Separation of Concerns for Token Accessibility

- Hash verification is limited to private key storage functions (LockSmith nodes)
- Token transactions use standard blockchain protocols without additional verification
- This separation ensures widespread token accessibility through existing wallets and exchanges
- Exchange and third-party wallet integrations can use standard token APIs without custom verification

### Admin Signing Workflow

As LockBox admin, the binary signing process includes:

1. **Final Build Preparation**: Release candidate prepared in secure, isolated build environment
2. **Hash Generation**: SHA-256 hash calculated for the complete binary
3. **Admin Signing Process**:
   - Admin private key (stored in offline, secure hardware device) used to sign the hash
   - Ed25519 algorithm used for security and efficiency
4. **Secondary Verification**: Release candidate and hash provided to security firm for verification and secondary signature
5. **Release Package Creation**: Final package contains binary, hash, both signatures, and manifest file
6. **Deployment**: Package deployed to LockBox-operated nodes via secure internal systems
7. **Key Management**: Admin signing key secured in hardware security module, used only in air-gapped environment

---

This approach maintains the security and integrity of the LockBox private key storage network while ensuring the LockBox token can be freely traded through standard cryptocurrency infrastructure.
