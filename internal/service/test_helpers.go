package service

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/payment"
)

// newTestServiceMinimal creates a minimal service for testing without full initialization.
// Use this for unit tests that don't need storage, ZKP, etc.
// Includes shardEncryptor for V2 encryption/decryption tests.
func newTestServiceMinimal(t *testing.T) *Service {
	t.Helper()

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	hkdf, err := crypto.NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("failed to create HKDF manager: %v", err)
	}

	shardEncryptor, err := crypto.NewShardEncryptor(masterKey, 4096)
	if err != nil {
		t.Fatalf("failed to create shard encryptor: %v", err)
	}

	return &Service{
		hkdfManager:    hkdf,
		shardEncryptor: shardEncryptor,
		lockedAssets:   make(map[string]*LockedAsset),
		config: &ServiceConfig{
			Tier: TierStandard,
		},
	}
}

// createTestRealShard creates a real shard for testing.
func createTestRealShard(t *testing.T, index uint32) *crypto.MixedShard {
	t.Helper()

	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate shard data: %v", err)
	}

	nonce := make([]byte, 24) // XChaCha20-Poly1305 nonce size
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	return &crypto.MixedShard{
		CharacterShard: crypto.CharacterShard{
			Index: index,
			Total: 10,
			Data:  data,
			Nonce: nonce,
		},
		ShardType:     crypto.ShardTypeReal,
		OriginalIndex: index,
	}
}

// createTestDecoyShard creates a decoy shard for testing.
func createTestDecoyShard(t *testing.T, index uint32) *crypto.MixedShard {
	t.Helper()

	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate shard data: %v", err)
	}

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	return &crypto.MixedShard{
		CharacterShard: crypto.CharacterShard{
			Index: index + 1000, // Offset for decoys
			Total: 10,
			Data:  data,
			Nonce: nonce,
		},
		ShardType:     crypto.ShardTypeDecoy,
		OriginalIndex: index,
	}
}

// createTestAssetWithShards creates an asset with specified shard counts for testing.
func createTestAssetWithShards(t *testing.T, realCount, totalCount int) *LockedAsset {
	t.Helper()

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("failed to generate asset ID: %v", err)
	}

	return &LockedAsset{
		ID:          string(id),
		TotalShards: totalCount,
		RealCount:   realCount,
		ShardCount:  realCount, // backward compatibility
		Salt:        salt,
		Status:      AssetStatusLocked,
	}
}

// createCorruptedAsset creates an asset with corrupted shards that cannot be decrypted.
func createCorruptedAsset(t *testing.T, realCount, totalCount int) *LockedAsset {
	t.Helper()

	asset := createTestAssetWithShards(t, realCount, totalCount)
	// Asset has no valid shards - recovery will always fail
	return asset
}

// deriveTestKey derives a key for testing using a fixed master key and salt.
func deriveTestKey(t *testing.T, bundleID string, position uint32) []byte {
	t.Helper()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(0xFF - i)
	}

	hkdf, err := crypto.NewHKDFManagerWithSalt(masterKey, salt)
	if err != nil {
		t.Fatalf("failed to create HKDF: %v", err)
	}
	defer hkdf.Clear()

	key, err := hkdf.DeriveKeyForPosition(bundleID, position)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	return key
}

// createTestPaymentToken creates and confirms a payment token for testing.
// This helper simulates the full payment flow without actual ledger integration.
//
// Usage:
//
//	paymentToken := createTestPaymentToken(t, svc, assetID)
//	svc.UnlockAsset(ctx, &UnlockAssetRequest{
//	    AssetID:      assetID,
//	    PaymentToken: paymentToken,
//	    ...
//	})
func createTestPaymentToken(t *testing.T, svc *Service, assetID string) string {
	t.Helper()

	ctx := context.Background()

	// Create payment
	createResp, err := svc.paymentProcessor.CreatePayment(ctx, payment.CreatePaymentRequest{
		AssetID:  assetID,
		Tier:     svc.config.Tier,
		FeeType:  payment.FeeTypeRetrieval,
		Currency: payment.CurrencyUSD,
	})
	if err != nil {
		t.Fatalf("failed to create payment: %v", err)
	}

	// Confirm payment (simulate ledger confirmation)
	err = svc.paymentProcessor.ConfirmPayment(ctx, createResp.PaymentToken, "test_tx_"+assetID)
	if err != nil {
		t.Fatalf("failed to confirm payment: %v", err)
	}

	return createResp.PaymentToken
}
