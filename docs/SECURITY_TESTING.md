# Security Testing Guidelines

## Why This Matters

In December 2025, we discovered **6 critical security vulnerabilities** that passed code review and tests:

| Function | What it claimed | What it did |
|----------|-----------------|-------------|
| `require_sigs()` | Verify Ed25519 multi-sig | Counted non-empty strings |
| `VerifySignature()` | Ed25519 verification | Compared 16 bytes of SHA256 |
| `validateAccessToken()` | Validate API token | `return token != ""` |
| `checkTokenNonce()` | Prevent replay attacks | `return nonce != ""` |
| `calculateChecksum()` | Cryptographic integrity | XOR (trivially forgeable) |
| `verifyChecksum()` | Secure comparison | Timing-vulnerable loop |

**Root cause:** Tests only checked happy paths, never verified that invalid input was rejected.

---

## Golden Rule

> **If a test passes with fake data, the function is broken.**

```go
// ❌ BAD: This test would pass with a broken implementation
func TestRequireSigs_Bad(t *testing.T) {
    signatures := []interface{}{"sig1", "sig2", "sig3"}  // Fake strings!
    result := funcRequireSigs(signatures, 2)
    require.True(t, result)  // Passes because len("sig1") > 0
}

// ✅ GOOD: Uses real cryptographic signatures
func TestRequireSigs_Good(t *testing.T) {
    pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
    sig1 := ed25519.Sign(priv1, []byte("message"))

    result := funcRequireSigs([][]byte{pub1}, "message", [][]byte{sig1}, 1)
    require.True(t, result)
}
```

---

## Required Test Categories

Every security-critical function MUST have these test types:

### 1. Valid Input (Happy Path)
```go
func TestVerifySignature_Valid(t *testing.T) {
    pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
    message := []byte("test message")
    signature := ed25519.Sign(privKey, message)

    result := VerifySignature(message, signature, pubKey)
    require.True(t, result)
}
```

### 2. Invalid/Fake Input (CRITICAL!)
```go
func TestVerifySignature_FakeSignature(t *testing.T) {
    pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
    message := []byte("test message")
    fakeSignature := make([]byte, 64)  // All zeros

    result := VerifySignature(message, fakeSignature, pubKey)
    require.False(t, result, "MUST reject fake signatures!")
}
```

### 3. Wrong Key/Token
```go
func TestVerifySignature_WrongKey(t *testing.T) {
    _, privKey1, _ := ed25519.GenerateKey(rand.Reader)
    pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)

    message := []byte("test message")
    signature := ed25519.Sign(privKey1, message)

    result := VerifySignature(message, signature, pubKey2)
    require.False(t, result, "MUST reject signature from different key!")
}
```

### 4. Malformed Input
```go
func TestVerifySignature_WrongSize(t *testing.T) {
    result := VerifySignature(
        []byte("message"),
        []byte("short"),      // Should be 64 bytes
        []byte("also short"), // Should be 32 bytes
    )
    require.False(t, result, "MUST reject malformed input!")
}
```

### 5. Replay Attack (for tokens/nonces)
```go
func TestCheckNonce_ReplayAttack(t *testing.T) {
    nonce := generateNonce()

    result1 := checkNonce(nonce)
    require.True(t, result1, "First use should succeed")

    result2 := checkNonce(nonce)
    require.False(t, result2, "MUST reject replayed nonce!")
}
```

### 6. Timing Attack (for comparisons)
```go
func TestVerifyChecksum_ConstantTime(t *testing.T) {
    data := []byte("test data")
    correctChecksum := calculateChecksum(data)

    // Should use hmac.Equal or subtle.ConstantTimeCompare
    // NOT: for loop with early return
}
```

---

## Code Review Checklist

Before approving ANY security-critical code:

### Implementation
- [ ] No `TODO` or `placeholder` comments in crypto code
- [ ] No `return input != ""` as validation
- [ ] Uses real crypto libraries (`crypto/ed25519`, `crypto/hmac`)
- [ ] Comparisons use `hmac.Equal()` or `subtle.ConstantTimeCompare()`
- [ ] Key/signature sizes are validated before use

### Tests
- [ ] Has test with VALID input → returns true/success
- [ ] Has test with FAKE input → returns false/error
- [ ] Has test with WRONG KEY → returns false
- [ ] Has test with MALFORMED input → returns false/error
- [ ] Has test for REPLAY ATTACK (if applicable)
- [ ] Uses real crypto keys, not string placeholders

### Red Flags
```go
// NEVER approve code like this:
return token != ""                    // ❌ Not validation
return len(signature) > 0             // ❌ Not verification
expected[:16] == actual[:16]          // ❌ Partial comparison
for i := range a { if a[i] != b[i] }  // ❌ Timing vulnerable
// TODO: implement actual verification // ❌ Placeholder in prod
```

---

## Test Templates

### Signature Verification
```go
func TestSignatureVerification(t *testing.T) {
    t.Run("Valid", func(t *testing.T) {
        pub, priv, _ := ed25519.GenerateKey(rand.Reader)
        msg := []byte("test")
        sig := ed25519.Sign(priv, msg)
        require.True(t, verify(msg, sig, pub))
    })

    t.Run("FakeSignature", func(t *testing.T) {
        pub, _, _ := ed25519.GenerateKey(rand.Reader)
        msg := []byte("test")
        fakeSig := make([]byte, 64)
        require.False(t, verify(msg, sig, pub))
    })

    t.Run("WrongKey", func(t *testing.T) {
        _, priv1, _ := ed25519.GenerateKey(rand.Reader)
        pub2, _, _ := ed25519.GenerateKey(rand.Reader)
        msg := []byte("test")
        sig := ed25519.Sign(priv1, msg)
        require.False(t, verify(msg, sig, pub2))
    })

    t.Run("TamperedMessage", func(t *testing.T) {
        pub, priv, _ := ed25519.GenerateKey(rand.Reader)
        sig := ed25519.Sign(priv, []byte("original"))
        require.False(t, verify([]byte("tampered"), sig, pub))
    })
}
```

### Token/Nonce Validation
```go
func TestTokenValidation(t *testing.T) {
    t.Run("Empty", func(t *testing.T) {
        require.False(t, validateToken(""))
    })

    t.Run("TooShort", func(t *testing.T) {
        require.False(t, validateToken("abc"))
    })

    t.Run("InvalidFormat", func(t *testing.T) {
        require.False(t, validateToken("not-hex-!!!"))
    })

    t.Run("Expired", func(t *testing.T) {
        token := createExpiredToken()
        require.False(t, validateToken(token))
    })

    t.Run("Replay", func(t *testing.T) {
        token := createValidToken()
        require.True(t, validateToken(token))
        require.False(t, validateToken(token)) // Same token again
    })
}
```

### Checksum/Integrity
```go
func TestChecksum(t *testing.T) {
    t.Run("Valid", func(t *testing.T) {
        data := []byte("test data")
        checksum := calculateChecksum(data)
        require.True(t, verifyChecksum(data, checksum))
    })

    t.Run("TamperedData", func(t *testing.T) {
        checksum := calculateChecksum([]byte("original"))
        require.False(t, verifyChecksum([]byte("tampered"), checksum))
    })

    t.Run("TamperedChecksum", func(t *testing.T) {
        data := []byte("test")
        checksum := calculateChecksum(data)
        checksum[0] ^= 0xFF
        require.False(t, verifyChecksum(data, checksum))
    })

    t.Run("WrongLength", func(t *testing.T) {
        data := []byte("test")
        require.False(t, verifyChecksum(data, []byte("short")))
    })
}
```

---

---

## Business Logic Testing

Security functions protect business operations. Test the full flow:

### Lock/Unlock Flow
```go
func TestLockUnlock_FullFlow(t *testing.T) {
    svc := setupTestService(t)

    // 1. Lock asset
    lockResp, err := svc.LockAsset(ctx, &LockAssetRequest{
        OwnerAddress: testAddr,
        OutputID:     testOutput,
        LockDuration: time.Hour,
        LockScript:   "after(unlock_time)",
    })
    require.NoError(t, err)
    require.Equal(t, AssetStatusLocked, lockResp.Status)

    // 2. Try unlock BEFORE time - MUST FAIL
    _, err = svc.UnlockAsset(ctx, &UnlockAssetRequest{
        AssetID: lockResp.AssetID,
    })
    require.Error(t, err, "Unlock before time MUST fail!")

    // 3. Wait for unlock time
    time.Sleep(time.Hour)

    // 4. Unlock AFTER time - should succeed
    unlockResp, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
        AssetID: lockResp.AssetID,
    })
    require.NoError(t, err)
    require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}
```

### Key Store/Get Flow
```go
func TestStoreGetKey_FullFlow(t *testing.T) {
    // 1. Store key
    bundleID, token, err := storeKey("my-secret-key", TierStandard)
    require.NoError(t, err)

    // 2. Get with CORRECT token
    key, err := getKey(bundleID, token)
    require.NoError(t, err)
    require.Equal(t, "my-secret-key", key)

    // 3. Get with WRONG token - MUST FAIL
    _, err = getKey(bundleID, "wrong-token")
    require.Error(t, err, "Wrong token MUST fail!")

    // 4. Get with WRONG bundleID - MUST FAIL
    _, err = getKey("wrong-bundle", token)
    require.Error(t, err, "Wrong bundle MUST fail!")
}
```

### Delete Key Flow
```go
func TestDeleteKey_FullFlow(t *testing.T) {
    svc := setupTestService(t)

    // 1. Store a key
    bundleID, token := storeTestKey(t, svc)

    // 2. Delete with valid token
    nonce := fmt.Sprintf("%d:random1234567890", time.Now().Unix())
    _, err := svc.DeleteKey(ctx, &DeleteKeyRequest{
        BundleID:    bundleID,
        AccessToken: token,
        Nonce:       nonce,
    })
    require.NoError(t, err)

    // 3. Try to get deleted key - MUST FAIL
    _, err = svc.GetKey(ctx, bundleID, token)
    require.Error(t, err, "Deleted key MUST not be retrievable!")

    // 4. Try to delete again (replay) - MUST FAIL
    _, err = svc.DeleteKey(ctx, &DeleteKeyRequest{
        BundleID:    bundleID,
        AccessToken: token,
        Nonce:       nonce, // Same nonce
    })
    require.Error(t, err, "Replay attack MUST fail!")
}
```

### Multi-Sig Flow
```go
func TestMultiSig_2of3(t *testing.T) {
    // Setup 3 signers
    pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
    pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
    pub3, priv3, _ := ed25519.GenerateKey(rand.Reader)

    message := "unlock-asset-123"

    // 1. Only 1 signature - MUST FAIL
    sig1 := ed25519.Sign(priv1, []byte(message))
    result := requireSigs(
        [][]byte{pub1, pub2, pub3},
        message,
        [][]byte{sig1, nil, nil},
        2,
    )
    require.False(t, result, "1-of-3 MUST fail for 2-of-3 threshold!")

    // 2. 2 valid signatures - should succeed
    sig2 := ed25519.Sign(priv2, []byte(message))
    result = requireSigs(
        [][]byte{pub1, pub2, pub3},
        message,
        [][]byte{sig1, sig2, nil},
        2,
    )
    require.True(t, result)

    // 3. 2 signatures but one fake - MUST FAIL
    fakeSig := make([]byte, 64)
    result = requireSigs(
        [][]byte{pub1, pub2, pub3},
        message,
        [][]byte{sig1, fakeSig, nil},
        2,
    )
    require.False(t, result, "1 valid + 1 fake MUST fail!")
}
```

### Authorization Boundaries
```go
func TestAuthorization_Boundaries(t *testing.T) {
    svc := setupTestService(t)

    // Create two different users
    user1Addr := generateTestAddress()
    user2Addr := generateTestAddress()

    // User1 locks an asset
    lockResp, _ := svc.LockAsset(ctx, &LockAssetRequest{
        OwnerAddress: user1Addr,
        OutputID:     testOutput,
        LockDuration: time.Hour,
    })

    // User2 tries to unlock User1's asset - MUST FAIL
    _, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
        AssetID:      lockResp.AssetID,
        OwnerAddress: user2Addr, // Wrong owner!
    })
    require.Error(t, err, "Wrong owner MUST not unlock!")
}
```

### Test Matrix

| Operation | Valid | Wrong Token | Wrong Owner | Expired | Replay |
|-----------|-------|-------------|-------------|---------|--------|
| LockAsset | ✓ | N/A | N/A | N/A | N/A |
| UnlockAsset | ✓ | ✓ | ✓ | ✓ | N/A |
| GetKey | ✓ | ✓ | ✓ | N/A | N/A |
| DeleteKey | ✓ | ✓ | ✓ | ✓ | ✓ |
| RotateKey | ✓ | ✓ | ✓ | ✓ | ✓ |

✓ = Test must exist and pass

---

## Lessons Learned

1. **Stubs look like real code** - A function returning `true` compiles and tests pass
2. **Happy path tests are necessary but not sufficient** - Must test rejection cases
3. **TODO comments get forgotten** - Never merge security placeholders
4. **Code review needs security focus** - Reviewers must ask "does this actually verify?"
5. **Use real crypto in tests** - `"sig1"` is not a signature

---

## Quick Reference

| What | Use | Don't Use |
|------|-----|-----------|
| Signatures | `ed25519.Verify()` | `len(sig) > 0` |
| Comparisons | `hmac.Equal()` | `for i := range` |
| Checksums | `sha256` / `hmac` | XOR |
| Validation | Full crypto verification | `!= ""` |
| Test data | Real keys/signatures | String placeholders |
