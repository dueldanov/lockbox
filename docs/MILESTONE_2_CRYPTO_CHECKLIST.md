# Milestone 2 Cryptographic Implementation Checklist

**Based on:** Crypto Audit Report (2026-01-12)
**Target:** Address compliance gaps and hardening

---

## M2.4: AES-256-GCM Migration

### Implementation Tasks

- [ ] **Create AES-256-GCM encryptor**
  - File: `internal/crypto/aead_aes.go`
  - Use `crypto/aes` + `crypto/cipher.NewGCM`
  - Maintain same interface as ChaCha20 version

- [ ] **Add encryption version flag**
  ```go
  type EncryptionVersion int
  const (
      VersionChaCha20  EncryptionVersion = 1  // Legacy
      VersionAES256GCM EncryptionVersion = 2  // Default
  )
  ```

- [ ] **Implement version selection**
  - Config option: `encryption_algorithm: "aes-256-gcm"`
  - Default to AES-256-GCM
  - Support ChaCha20 for backward compatibility

- [ ] **Update shard encryption**
  - `ShardEncryptor.EncryptDataV3()` with version parameter
  - Store version in shard metadata
  - Auto-detect on decryption

- [ ] **Migration tool**
  - `cmd/migrate-encryption`: Convert ChaCha20 → AES-256-GCM
  - Decrypt with old algorithm, re-encrypt with new
  - Batch processing with progress bar

### Testing Requirements

- [ ] **AES-256-GCM test suite**
  - Copy all ChaCha20 tests to `aead_aes_test.go`
  - Verify authentication failure detection (11 scenarios)
  - Verify wrong key rejection
  - Verify constant-time operation

- [ ] **Cross-version compatibility**
  - Test ChaCha20 encrypt → AES-256-GCM decrypt (should fail)
  - Test version detection from metadata
  - Test migration tool on sample data

- [ ] **Performance benchmarks**
  ```bash
  go test -bench=BenchmarkAES256GCM ./internal/crypto/...
  go test -bench=BenchmarkChaCha20 ./internal/crypto/...
  ```
  - Compare throughput (MB/s)
  - Compare latency (µs per operation)
  - Document AES-NI requirement for performance

### Documentation

- [ ] **Update LOCKBOX_REQUIREMENTS.md**
  - Change Section 3.1.1: "Encryption: AES-256-GCM ✅ (was ChaCha20-Poly1305)"
  - Document algorithm selection

- [ ] **Migration guide**
  - File: `docs/ENCRYPTION_MIGRATION_GUIDE.md`
  - Steps for existing deployments
  - Downtime expectations (if any)
  - Rollback procedure

---

## M2.5: BIP-39 Seed Phrase Integration

### Implementation Tasks

- [ ] **Add BIP-39 library**
  ```bash
  go get github.com/tyler-smith/go-bip39
  ```

- [ ] **Create seedphrase module**
  - File: `internal/crypto/seedphrase.go`
  - Function: `GenerateSeedPhrase() (mnemonic string, entropy []byte, err error)`
  - Function: `SeedPhraseToMasterKey(mnemonic, passphrase string) ([]byte, error)`
  - Function: `ValidateSeedPhrase(mnemonic string) error`

- [ ] **Integrate with LockAsset**
  ```go
  // Generate Direct Key Recovery Seed Phrase
  seedPhrase, entropy, _ := GenerateSeedPhrase()

  // Display to user
  resp.RecoverySeedPhrase = seedPhrase

  // Optionally encrypt and store
  encryptedSeed := encryptSeedPhrase(seedPhrase, userPassword)
  storage.SaveSeedPhrase(assetID, encryptedSeed)
  ```

- [ ] **Recovery workflow**
  - New function: `RecoverKeyFromSeedPhrase(mnemonic, passphrase string) ([]byte, error)`
  - Integration with UnlockAsset
  - Fallback if network unavailable

### Testing Requirements

- [ ] **Seed phrase generation tests**
  - Test 24-word generation
  - Test entropy randomness (128/256 bits)
  - Test mnemonic validation (checksum)
  - Test passphrase requirement (min 12 chars)

- [ ] **Key derivation tests**
  - Test deterministic derivation (same seed = same key)
  - Test passphrase changes derivation
  - Test compatibility with BIP-39 standard

- [ ] **Recovery tests**
  - Test full recovery from seed phrase
  - Test recovery with wrong passphrase (should fail)
  - Test recovery with corrupted seed (should fail)

### Documentation

- [ ] **Update LOCKBOX_REQUIREMENTS.md**
  - Section 3.5: Add implementation status ✅
  - Document seed phrase format
  - Document passphrase requirements

- [ ] **User guide**
  - File: `docs/SEED_PHRASE_GUIDE.md`
  - How to record seed phrase securely
  - Recovery instructions
  - Warning about passphrase importance

---

## M2.6: HSM Integration (Elite Tier)

### Implementation Tasks

- [ ] **Create HSM interface**
  ```go
  // internal/crypto/hsm.go
  type HSMAdapter interface {
      StoreKey(keyID string, key []byte) error
      RetrieveKey(keyID string) ([]byte, error)
      Sign(keyID string, message []byte) ([]byte, error)
      Encrypt(keyID string, plaintext []byte) ([]byte, error)
      Decrypt(keyID string, ciphertext []byte) ([]byte, error)
  }
  ```

- [ ] **Windows TPM adapter**
  - File: `internal/crypto/hsm_windows.go`
  - Use CNG API
  - TPM 2.0 support
  - Build tag: `// +build windows`

- [ ] **Android Keystore adapter**
  - File: `internal/crypto/hsm_android.go`
  - Use hardware-backed keystore
  - Requires `gomobile` integration
  - Build tag: `// +build android`

- [ ] **Fallback to file-based**
  - Non-Elite tiers use existing KeyStore
  - Elite tier checks HSM availability
  - Graceful degradation if HSM unavailable

### Testing Requirements

- [ ] **Mock HSM adapter**
  - File: `internal/crypto/hsm_mock.go`
  - For unit testing without hardware

- [ ] **HSM adapter tests**
  - Test key storage and retrieval
  - Test signing operations
  - Test encryption/decryption
  - Test error handling (HSM unavailable)

- [ ] **Platform-specific tests**
  - Windows: Test TPM 2.0 integration
  - Android: Test hardware-backed keystore
  - Test fallback behavior

### Documentation

- [ ] **Update LOCKBOX_REQUIREMENTS.md**
  - Section 3.9.2: Add implementation status ✅
  - Document platform support

- [ ] **HSM setup guide**
  - File: `docs/HSM_SETUP_GUIDE.md`
  - Windows TPM setup instructions
  - Android keystore configuration
  - Troubleshooting

---

## M2.7: Security Hardening

### Memory Protection

- [ ] **Implement mlock() for Unix**
  ```go
  // internal/crypto/memory_unix.go
  func lockMemory(b []byte) error {
      return syscall.Mlock(b)
  }

  func unlockMemory(b []byte) error {
      return syscall.Munlock(b)
  }
  ```

- [ ] **Implement VirtualLock() for Windows**
  ```go
  // internal/crypto/memory_windows.go
  func lockMemory(b []byte) error {
      return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
  }
  ```

- [ ] **Update HKDFManager**
  - Lock master key memory
  - Lock derived key memory
  - Unlock on Clear()

### ZKP Nonce Tracking

- [ ] **Create nonce tracker**
  ```go
  // internal/verification/nonce_tracker.go
  type NonceTracker struct {
      used map[string]time.Time  // nonce -> timestamp
      mu   sync.RWMutex
  }

  func (nt *NonceTracker) CheckAndMark(nonce string) error {
      if nt.IsUsed(nonce) {
          return ErrNonceReplay
      }
      nt.Mark(nonce)
      return nil
  }
  ```

- [ ] **Integrate with ZKP verification**
  - Check nonce before verifying proof
  - Mark nonce as used after successful verification
  - 5-minute validation window

- [ ] **Cleanup expired nonces**
  - Background goroutine
  - Remove nonces older than 5 minutes
  - Run every 1 minute

### Testing Requirements

- [ ] **Memory lock tests**
  - Test mlock() success
  - Test unlock on Clear()
  - Test fallback if mlock() fails (non-root)

- [ ] **Nonce replay tests**
  - Test valid nonce accepted
  - Test reused nonce rejected (CRITICAL)
  - Test expired nonce cleaned up
  - Test concurrent access

### Documentation

- [ ] **Update security documentation**
  - Document memory locking behavior
  - Document nonce replay protection
  - Document limitations (requires root for mlock)

---

## Verification Checklist

### Before Milestone 2 Complete

- [ ] All M2.4 tasks completed (AES-256-GCM)
- [ ] All M2.5 tasks completed (BIP-39)
- [ ] All M2.6 tasks completed (HSM for Elite)
- [ ] All M2.7 tasks completed (Security hardening)

### Testing

- [ ] All new tests passing (100%)
- [ ] Benchmark performance (AES vs ChaCha20)
- [ ] Cross-platform testing (Windows, Linux, Android)
- [ ] HSM integration testing (TPM, Keystore)

### Documentation

- [ ] LOCKBOX_REQUIREMENTS.md updated
- [ ] Migration guides written
- [ ] User guides written
- [ ] API documentation updated

### Security Review

- [ ] Re-run crypto audit
- [ ] Verify AES-256-GCM compliance
- [ ] Verify HSM integration
- [ ] Verify memory protection
- [ ] Verify nonce replay protection

---

## Timeline Estimate

| Task | Complexity | Estimated Time |
|------|------------|----------------|
| M2.4 AES-256-GCM | Medium | 3-5 days |
| M2.5 BIP-39 | Low | 1-2 days |
| M2.6 HSM (Windows) | High | 5-7 days |
| M2.6 HSM (Android) | High | 5-7 days |
| M2.7 Hardening | Medium | 2-3 days |
| Testing | Medium | 3-5 days |
| Documentation | Low | 2-3 days |

**Total:** 21-32 days (4-6 weeks)

---

## Success Criteria

✅ **Milestone 2 is complete when:**

1. AES-256-GCM encryption is default
2. BIP-39 seed phrases are generated and work for recovery
3. Elite tier can use HSM (TPM on Windows, Keystore on Android)
4. Memory is locked for sensitive data
5. ZKP replay attacks are prevented
6. All tests pass (100%)
7. Documentation is updated
8. Crypto audit shows 0 compliance gaps

---

**Document Version:** 1.0
**Created:** 2026-01-12
**Updated:** 2026-01-12
