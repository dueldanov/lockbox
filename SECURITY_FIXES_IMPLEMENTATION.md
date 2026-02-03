# LockBox Security Fixes - Implementation Guide

**Priority Order:** CRITICAL → HIGH → MEDIUM
**Timeline:** Deploy CRITICAL fixes within 24 hours

---

## CRITICAL FIX #1: Payment Double-Spend Race Condition

### Problem Location
```
File: internal/payment/processor.go
Lines: 288-349 (VerifyPayment)
Lines: 379-405 (MarkPaymentUsed)

File: internal/service/service.go
Lines: 1054-1074 (verification call)
Lines: 1480 (marking as used - too late!)
```

### Root Cause Analysis
```
Timeline of vulnerable code:
1. Request A and Request B both call VerifyPayment()
2. Both check payment.Status == PaymentStatusConfirmed
3. Both return Valid=true
4. Both proceed with unlock operation
5. First completes, calls MarkPaymentUsed()
6. Second completes, calls MarkPaymentUsed() again
Result: Payment used twice
```

### Fix Implementation

#### Step 1: Modify PaymentProcessor

```go
// File: internal/payment/processor.go

// NEW METHOD: Atomic verify-and-mark operation
// VerifyAndMarkPaymentUsed atomically verifies payment is valid and marks it as used.
// This prevents double-spend race conditions by ensuring only one caller can succeed.
//
// SECURITY: The entire operation (verify + mark) happens under a single lock.
// This prevents TOCTOU (time-of-check-to-time-of-use) race conditions.
func (p *PaymentProcessor) VerifyAndMarkPaymentUsed(ctx context.Context, req VerifyPaymentRequest) (*VerifyPaymentResponse, error) {
	p.mu.Lock() // CRITICAL: Lock FIRST before any checks
	defer p.mu.Unlock()

	// 1. Lookup payment by token (inside lock)
	paymentID, ok := p.tokenToPaymentID[req.PaymentToken]
	if !ok {
		return &VerifyPaymentResponse{
			Valid: false,
			Error: "payment token not found",
		}, nil
	}

	payment, ok := p.payments[paymentID]
	if !ok {
		return &VerifyPaymentResponse{
			Valid: false,
			Error: "payment record not found",
		}, nil
	}

	// 2. Verify payment matches asset (inside lock)
	if payment.AssetID != req.AssetID {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     "payment token not valid for this asset",
		}, nil
	}

	// 3. Check if already used (inside lock)
	if payment.Status == PaymentStatusUsed {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     "payment already used",
		}, nil
	}

	// 4. Check expiry (inside lock)
	if time.Now().After(payment.ExpiresAt) {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     "payment token expired",
		}, nil
	}

	// 5. Check payment is confirmed (inside lock)
	if payment.Status != PaymentStatusConfirmed {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     fmt.Sprintf("payment not confirmed: status=%s", payment.Status),
		}, nil
	}

	// 6. CRITICAL: Mark as used IMMEDIATELY (still inside lock)
	now := time.Now()
	payment.Status = PaymentStatusUsed
	payment.UsedAt = &now

	// 7. Return success (lock released after this)
	return &VerifyPaymentResponse{
		Valid:     true,
		PaymentID: paymentID,
		AmountUSD: payment.AmountUSD,
	}, nil
}

// DEPRECATED: Old VerifyPayment method - mark as deprecated
// Use VerifyAndMarkPaymentUsed instead to prevent race conditions.
//
// Deprecated: This method is vulnerable to race conditions.
// Use VerifyAndMarkPaymentUsed which atomically verifies and marks the payment.
func (p *PaymentProcessor) VerifyPayment(ctx context.Context, req VerifyPaymentRequest) (*VerifyPaymentResponse, error) {
	// Keep old implementation for backwards compatibility
	// but log warning
	log.Printf("WARNING: VerifyPayment is deprecated and vulnerable to race conditions. Use VerifyAndMarkPaymentUsed.")

	// ... existing implementation ...
}

// MarkPaymentUsed is now a no-op if payment already marked by VerifyAndMarkPaymentUsed
func (p *PaymentProcessor) MarkPaymentUsed(ctx context.Context, paymentToken string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	paymentID, ok := p.tokenToPaymentID[paymentToken]
	if !ok {
		return ErrPaymentNotFound
	}

	payment, ok := p.payments[paymentID]
	if !ok {
		return ErrPaymentNotFound
	}

	// Already marked by VerifyAndMarkPaymentUsed - success
	if payment.Status == PaymentStatusUsed {
		return nil
	}

	// Should not reach here in new flow, but handle for safety
	now := time.Now()
	payment.Status = PaymentStatusUsed
	payment.UsedAt = &now

	return nil
}
```

#### Step 2: Update Service to Use New Method

```go
// File: internal/service/service.go
// Lines: 1054-1074

// OLD CODE (REMOVE):
/*
verifyResp, err := s.paymentProcessor.VerifyPayment(ctx, payment.VerifyPaymentRequest{
    PaymentToken: req.PaymentToken,
    AssetID:      req.AssetID,
})
if err != nil {
    log.LogStepWithDuration(logging.PhasePayment, "validate_payment_tx",
        fmt.Sprintf("verificationError=%v", err), time.Since(stepStart), err)
    return nil, fmt.Errorf("payment verification failed: %w", err)
}
if !verifyResp.Valid {
    log.LogStepWithDuration(logging.PhasePayment, "validate_payment_tx",
        fmt.Sprintf("valid=false, reason=%s", verifyResp.Error), time.Since(stepStart),
        fmt.Errorf("payment invalid: %s", verifyResp.Error))
    return nil, fmt.Errorf("payment invalid: %s", verifyResp.Error)
}
*/

// NEW CODE:
stepStart = time.Now()
if req.PaymentToken == "" {
    log.LogStepWithDuration(logging.PhasePayment, "validate_payment_tx",
        "paymentTokenMissing=true", time.Since(stepStart), fmt.Errorf("payment token required"))
    return nil, fmt.Errorf("payment token is required for unlock")
}

// SECURITY FIX: Atomically verify AND mark payment as used
// This prevents double-spend race conditions
verifyResp, err := s.paymentProcessor.VerifyAndMarkPaymentUsed(ctx, payment.VerifyPaymentRequest{
    PaymentToken: req.PaymentToken,
    AssetID:      req.AssetID,
})
if err != nil {
    log.LogStepWithDuration(logging.PhasePayment, "validate_payment_tx",
        fmt.Sprintf("verificationError=%v", err), time.Since(stepStart), err)
    return nil, fmt.Errorf("payment verification failed: %w", err)
}
if !verifyResp.Valid {
    log.LogStepWithDuration(logging.PhasePayment, "validate_payment_tx",
        fmt.Sprintf("valid=false, reason=%s", verifyResp.Error), time.Since(stepStart),
        fmt.Errorf("payment invalid: %s", verifyResp.Error))
    return nil, fmt.Errorf("payment invalid: %s", verifyResp.Error)
}
log.LogStepWithDuration(logging.PhasePayment, "validate_payment_tx",
    fmt.Sprintf("valid=true, paymentID=%s, amount=$%.4f, atomicallyMarkedUsed=true",
        verifyResp.PaymentID, verifyResp.AmountUSD),
    time.Since(stepStart), nil)

// REMOVE line 1074: paymentToken := req.PaymentToken (no longer needed)

// REMOVE lines 1480-1487: MarkPaymentUsed call (already done atomically)
/*
if err := s.paymentProcessor.MarkPaymentUsed(ctx, paymentToken); err != nil {
    // ... this is now redundant ...
}
*/
```

#### Step 3: Add Comprehensive Tests

```go
// File: internal/payment/processor_test.go

func TestVerifyAndMarkPaymentUsed_RaceCondition(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create and confirm a payment
	createResp, _ := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "test-asset",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx-123")

	// Simulate race: 100 concurrent verify-and-mark attempts
	var wg sync.WaitGroup
	successCount := atomic.Int32{}
	failCount := atomic.Int32{}

	start := make(chan struct{})

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			verifyResp, err := processor.VerifyAndMarkPaymentUsed(ctx, VerifyPaymentRequest{
				PaymentToken: createResp.PaymentToken,
				AssetID:      "test-asset",
			})

			if err == nil && verifyResp.Valid {
				successCount.Add(1)
			} else {
				failCount.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	// SECURITY ASSERTION: Exactly ONE should succeed
	require.Equal(t, int32(1), successCount.Load(),
		"SECURITY VIOLATION: %d concurrent verifications succeeded (expected 1). "+
			"Payment double-spend vulnerability still exists!", successCount.Load())

	// All others should fail
	require.Equal(t, int32(99), failCount.Load(),
		"Expected 99 failures, got %d", failCount.Load())

	// Verify payment is marked as used
	payment, _ := processor.GetPaymentByToken(ctx, createResp.PaymentToken)
	require.Equal(t, PaymentStatusUsed, payment.Status)
	require.NotNil(t, payment.UsedAt)
}

func TestVerifyAndMarkPaymentUsed_AlreadyUsed(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	createResp, _ := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "test-asset",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx-123")

	// First call - should succeed
	verifyResp1, _ := processor.VerifyAndMarkPaymentUsed(ctx, VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "test-asset",
	})
	require.True(t, verifyResp1.Valid)

	// Second call - should fail (already used)
	verifyResp2, _ := processor.VerifyAndMarkPaymentUsed(ctx, VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "test-asset",
	})
	require.False(t, verifyResp2.Valid)
	require.Contains(t, verifyResp2.Error, "already used")
}
```

### Verification Steps

1. Run race detector:
   ```bash
   go test -race ./internal/payment/... -v -run TestVerifyAndMarkPaymentUsed
   ```

2. Run existing security tests:
   ```bash
   go test ./internal/service/... -v -run TestPaymentDoubleSpend
   ```

3. Load test (100 concurrent requests):
   ```bash
   go test -count=10 -parallel=100 ./internal/payment/... -v
   ```

4. Verify metrics:
   - Payment verification latency should increase by <5ms
   - No payment should succeed twice

### Rollback Plan

If issues arise:
1. Revert to old VerifyPayment + MarkPaymentUsed pattern
2. Add mutex around entire UnlockAsset function (coarse-grained lock)
3. Monitor for double-spend attempts

---

## CRITICAL FIX #2: Rate Limiter Per-User

### Problem Location
```
File: internal/service/service.go
Line: 952
```

### Root Cause
```go
// WRONG: Rate limits per asset, allowing amplification
if err := s.rateLimiter.Allow(req.AssetID); err != nil {
```

**Attack:**
- Attacker with 1000 assets
- 5 req/min per asset
- Total: 5000 req/min (should be 5)

### Fix Implementation

```go
// File: internal/service/service.go
// Line: 949-963

// OLD CODE (REMOVE):
// if err := s.rateLimiter.Allow(req.AssetID); err != nil {

// NEW CODE:
// #0 rate_limit_check — SECURITY: Prevent brute-force attacks (5 req/min per USER)
// SECURITY FIX: Rate limit by USER (owner address) instead of asset ID
// This prevents amplification attacks where attacker with N assets gets N×5 attempts/min
stepStart := time.Now()
if s.rateLimiter != nil {
    // Extract user ID from owner address
    userID := ""
    if req.OwnerAddress != nil {
        userID = req.OwnerAddress.String()
    }

    // Fallback to asset ID if owner address not provided (backwards compat)
    if userID == "" {
        userID = req.AssetID
        s.LogWarnf("Rate limiting by asset ID (no owner address) - this allows amplification attacks!")
    }

    if err := s.rateLimiter.Allow(userID); err != nil {
        retryAfter := s.rateLimiter.GetRetryAfter(userID)
        log.LogStepWithDuration(logging.PhaseTokenValidation, "rate_limit_check",
            fmt.Sprintf("rateLimited=true, userID=%s, retryAfter=%v", userID, retryAfter),
            time.Since(stepStart), err)
        return nil, &RateLimitError{
            Message:    fmt.Sprintf("rate limit exceeded: maximum 5 unlock attempts per minute per user (userID: %s)", userID),
            RetryAfter: retryAfter,
        }
    }
    log.LogStepWithDuration(logging.PhaseTokenValidation, "rate_limit_check",
        fmt.Sprintf("allowed=true, userID=%s", userID), time.Since(stepStart), nil)
}
```

### Update UnlockAssetRequest to Include Owner Address

```go
// File: internal/service/types.go

type UnlockAssetRequest struct {
    AssetID      string
    PaymentToken string
    Signatures   [][]byte
    UnlockParams map[string]interface{}
    AccessToken  string
    Nonce        string

    // ADDED: Owner address for rate limiting
    // This should be provided by the client making the unlock request
    OwnerAddress iotago.Address `json:"owner_address,omitempty"`
}
```

### Add Tests

```go
// File: internal/service/security_bugs_test.go

func TestRateLimiter_PerUser_NotPerAsset(t *testing.T) {
    svc := setupTestService(t)
    ctx := context.Background()

    // Create one user with 100 assets
    ownerAddr := generateTestAddress()

    // Try to unlock all 100 assets rapidly (5 attempts each)
    totalAttempts := 0
    for assetNum := 0; assetNum < 100; assetNum++ {
        assetID := fmt.Sprintf("asset-%d", assetNum)

        // Try 5 unlocks for this asset
        for attempt := 0; attempt < 5; attempt++ {
            _, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
                AssetID:      assetID,
                OwnerAddress: ownerAddr,
                PaymentToken: "test-token",
            })

            if err == nil || !errors.Is(err, ErrRateLimited) {
                totalAttempts++
            }
        }
    }

    // SECURITY ASSERTION: Should be rate limited after 5 attempts TOTAL
    // Not 5 × 100 = 500 attempts
    require.LessOrEqual(t, totalAttempts, 5,
        "Rate limiter allows %d attempts (expected ≤5). "+
        "Per-asset rate limiting vulnerability still exists!", totalAttempts)
}

func TestRateLimiter_DifferentUsers_IndependentLimits(t *testing.T) {
    svc := setupTestService(t)
    ctx := context.Background()

    user1 := generateTestAddress()
    user2 := generateTestAddress()

    // User1 makes 5 attempts - should all succeed
    for i := 0; i < 5; i++ {
        _, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
            AssetID:      "asset-1",
            OwnerAddress: user1,
            PaymentToken: createTestPaymentToken(t, svc, "asset-1"),
        })
        // May fail for other reasons, but not rate limit
        if err != nil {
            var rateLimitErr *RateLimitError
            require.False(t, errors.As(err, &rateLimitErr),
                "User1 rate limited at attempt %d", i+1)
        }
    }

    // User2 should still have full quota (independent)
    for i := 0; i < 5; i++ {
        _, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
            AssetID:      "asset-2",
            OwnerAddress: user2,
            PaymentToken: createTestPaymentToken(t, svc, "asset-2"),
        })
        if err != nil {
            var rateLimitErr *RateLimitError
            require.False(t, errors.As(err, &rateLimitErr),
                "User2 rate limited at attempt %d (should be independent from user1)", i+1)
        }
    }

    // User1's 6th attempt should fail
    _, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
        AssetID:      "asset-1",
        OwnerAddress: user1,
        PaymentToken: createTestPaymentToken(t, svc, "asset-1"),
    })

    var rateLimitErr *RateLimitError
    require.True(t, errors.As(err, &rateLimitErr),
        "User1 should be rate limited after 5 attempts")
}
```

### Verification Steps

1. Test amplification prevention:
   ```bash
   go test ./internal/service/... -v -run TestRateLimiter_PerUser
   ```

2. Load test with multiple users:
   ```bash
   # Verify each user limited independently
   go test -count=5 ./internal/service/... -v -run TestRateLimiter_DifferentUsers
   ```

3. Monitor metrics:
   - Rate limit hits should be per-user, not per-asset
   - No single user should exceed 5 req/min

---

## HIGH FIX #1: Constant-Time Token Comparison

### Problem Location
```
File: internal/service/delete.go
Lines: 603-647
```

### Root Cause
```go
// Early returns leak timing information
if token == "" {
    return false // Fast path for empty
}
if len(parts) != 2 {
    return false // Fast path for invalid format
}
if len(payload) != 64 {
    return false // Fast path for wrong length
}
// These different code paths have different execution times
```

### Fix Implementation

```go
// File: internal/service/delete.go
// Replace validateAccessToken function entirely

// validateAccessToken validates the single-use API key with HMAC verification.
// Token format: "payload:hmac" where:
//   - payload: 64 hex chars (32 bytes of token data)
//   - hmac: 64 hex chars (HMAC-SHA256 signature)
//
// SECURITY: Uses constant-time comparison to prevent timing attacks.
// All code paths take approximately the same time to prevent timing side-channels.
func (s *Service) validateAccessToken(token string) bool {
    // Use dummy values for invalid tokens (constant-time)
    payload := ""
    providedHMAC := ""

    // Parse token (always executes, no early return)
    parts := strings.SplitN(token, ":", 2)
    if len(parts) == 2 {
        payload = parts[0]
        providedHMAC = parts[1]
    }

    // Always decode HMAC (even if invalid) for constant time
    // Invalid hex will result in providedMAC with wrong length
    providedMAC, _ := hex.DecodeString(providedHMAC)

    // Always calculate expected HMAC (even for invalid payload)
    // This ensures consistent timing
    expectedMAC := calculateTokenHMAC(payload)

    // Validate lengths using constant-time operations
    // Use bitwise OR to combine checks without early return
    lengthValid := 1
    if len(payload) != 64 {
        lengthValid = 0
    }
    if len(providedHMAC) != 64 {
        lengthValid = 0
    }
    if len(providedMAC) != 32 {
        lengthValid = 0
    }
    if len(expectedMAC) != 32 {
        lengthValid = 0
    }

    // Pad MACs to same length if needed (for constant-time comparison)
    if len(providedMAC) < 32 {
        providedMAC = append(providedMAC, make([]byte, 32-len(providedMAC))...)
    }
    if len(expectedMAC) < 32 {
        expectedMAC = append(expectedMAC, make([]byte, 32-len(expectedMAC))...)
    }

    // SECURITY: Use hmac.Equal for constant-time HMAC comparison
    // This prevents timing attacks by always comparing all bytes
    macValid := hmac.Equal(expectedMAC, providedMAC)

    // Combine checks using constant-time logic
    // Both macValid AND lengthValid must be true
    return macValid && (lengthValid == 1)
}
```

### Add Timing Attack Test

```go
// File: internal/service/security_bugs_test.go

func TestValidateAccessToken_ConstantTime(t *testing.T) {
    os.Setenv("LOCKBOX_DEV_MODE", "true")
    reinitTokenHMACKey()
    defer os.Setenv("LOCKBOX_DEV_MODE", "true")

    svc := &Service{}

    // Generate valid token
    validToken, _ := GenerateAccessToken()
    parts := strings.Split(validToken, ":")
    validPayload := parts[0]
    validHMAC := parts[1]

    // Test cases with errors at different positions
    testCases := []struct {
        name    string
        token   string
    }{
        {"valid", validToken},
        {"empty", ""},
        {"wrong_format", validPayload},
        {"first_byte_wrong_hmac", validPayload + ":00" + validHMAC[2:]},
        {"middle_byte_wrong_hmac", validPayload + ":" + validHMAC[:32] + "00" + validHMAC[34:]},
        {"last_byte_wrong_hmac", validPayload + ":" + validHMAC[:62] + "00"},
        {"all_wrong_hmac", validPayload + ":" + strings.Repeat("00", 32)},
        {"short_payload", "abc:" + validHMAC},
        {"long_payload", validPayload + "00:" + validHMAC},
    }

    iterations := 10000
    timings := make(map[string]time.Duration)

    for _, tc := range testCases {
        start := time.Now()
        for i := 0; i < iterations; i++ {
            svc.validateAccessToken(tc.token)
        }
        timings[tc.name] = time.Since(start)
    }

    // Check timing consistency
    baseTime := timings["valid"]
    maxVariance := 0.0

    for name, timing := range timings {
        ratio := float64(timing) / float64(baseTime)
        variance := math.Abs(ratio - 1.0)

        if variance > maxVariance {
            maxVariance = variance
        }

        t.Logf("Timing %s: %v (ratio: %.3f, variance: %.1f%%)",
            name, timing, ratio, variance*100)
    }

    // SECURITY ASSERTION: Timing variance should be < 10%
    // Constant-time code should have similar execution times
    require.Less(t, maxVariance, 0.10,
        "Timing variance %.1f%% exceeds 10%% threshold. "+
        "Code is NOT constant-time and vulnerable to timing attacks!", maxVariance*100)
}
```

### Verification Steps

1. Run timing test:
   ```bash
   go test ./internal/service/... -v -run TestValidateAccessToken_ConstantTime
   ```

2. Check variance is < 10%

3. Use go-critic tool:
   ```bash
   go-critic check -enable timingCompare ./internal/service/
   ```

---

## Summary of Code Changes

### Files Modified

1. `internal/payment/processor.go`
   - Added: `VerifyAndMarkPaymentUsed()` method
   - Modified: `MarkPaymentUsed()` to handle already-marked payments
   - Deprecated: `VerifyPayment()` with warning

2. `internal/service/service.go`
   - Lines 1054-1074: Changed to use `VerifyAndMarkPaymentUsed()`
   - Lines 1480-1487: Removed redundant `MarkPaymentUsed()` call
   - Line 952: Changed from `req.AssetID` to user ID

3. `internal/service/types.go`
   - Added: `OwnerAddress` field to `UnlockAssetRequest`

4. `internal/service/delete.go`
   - Lines 603-647: Replaced `validateAccessToken()` with constant-time version

5. `internal/payment/processor_test.go`
   - Added: `TestVerifyAndMarkPaymentUsed_RaceCondition()`
   - Added: `TestVerifyAndMarkPaymentUsed_AlreadyUsed()`

6. `internal/service/security_bugs_test.go`
   - Added: `TestRateLimiter_PerUser_NotPerAsset()`
   - Added: `TestRateLimiter_DifferentUsers_IndependentLimits()`
   - Added: `TestValidateAccessToken_ConstantTime()`

### Testing Checklist

- [ ] All tests pass: `go test ./...`
- [ ] Race detector clean: `go test -race ./...`
- [ ] Load test 100 concurrent requests
- [ ] Timing variance < 10%
- [ ] No payment double-spend possible
- [ ] Rate limit per-user enforced
- [ ] Backwards compatibility maintained

### Deployment Checklist

- [ ] Code review by 2+ engineers
- [ ] Security team approval
- [ ] Staging deployment + smoke test
- [ ] Canary release (10% traffic)
- [ ] Monitor metrics for 24h
- [ ] Full rollout if no issues

### Rollback Plan

If critical issues found:
1. Revert payment changes → original VerifyPayment + MarkPaymentUsed
2. Revert rate limiter → per-asset (with monitoring)
3. Revert token validation → original (with timing attack risk acknowledged)

### Monitoring Alerts

Set up alerts for:
- Payment verification time > 100ms
- Rate limit hits > 1000/hour per user
- Token validation failures > 10/min
- Any payment marked as used twice (should never happen)

---

## Contact

Questions about implementation:
- Security Team: security@lockbox.io
- On-call Engineer: oncall@lockbox.io

**End of Implementation Guide**
