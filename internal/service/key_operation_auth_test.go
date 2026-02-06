package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/stretchr/testify/require"
)

func ensureTokenTestMode() {
	DevMode = true
	reinitTokenHMACKey()
}

func newNonceForTest() string {
	return fmt.Sprintf("%d:test_nonce_%d", time.Now().Unix(), time.Now().UnixNano())
}

func signForTest(pub ed25519.PublicKey, priv ed25519.PrivateKey, message string) []byte {
	sig := ed25519.Sign(priv, []byte(message))
	out := make([]byte, 0, 96)
	out = append(out, pub...)
	out = append(out, sig...)
	return out
}

func TestVerifyKeyOperationAuthorization_DomainSeparation_RotateVsDelete(t *testing.T) {
	svc := setupTestService(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ownerAddr := iotago.Ed25519AddressFromPubKey(pub)

	asset := &LockedAsset{
		ID:           "asset-domain-separation",
		OwnerAddress: &ownerAddr,
	}

	nonce := newNonceForTest()
	rotateMessage := buildRotateKeyMultiSigMessage(asset.ID, nonce)
	deleteMessage := buildDeleteKeyMultiSigMessage(asset.ID, nonce)
	require.NotEqual(t, rotateMessage, deleteMessage)

	rotateSig := signForTest(pub, priv, rotateMessage)

	err = svc.verifyKeyOperationAuthorization("delete", deleteMessage, [][]byte{rotateSig}, asset)
	require.Error(t, err)
	require.Contains(t, err.Error(), "owner signature required")
}

func TestVerifyKeyOperationAuthorization_MultiSigRejectsInvalidThreshold(t *testing.T) {
	svc := setupTestService(t)

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	addr1 := iotago.Ed25519AddressFromPubKey(pub1)
	addr2 := iotago.Ed25519AddressFromPubKey(pub2)

	asset := &LockedAsset{
		ID:                "asset-multisig-threshold",
		MultiSigAddresses: []iotago.Address{&addr1, &addr2},
		MinSignatures:     2,
	}

	nonce := newNonceForTest()
	msg := buildRotateKeyMultiSigMessage(asset.ID, nonce)
	onlyOneValidSig := signForTest(pub1, priv1, msg)

	err = svc.verifyKeyOperationAuthorization("rotate", msg, [][]byte{onlyOneValidSig}, asset)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient signatures")
}

func TestRotateKey_FailClosed_RequiresOwnerSignature(t *testing.T) {
	ensureTokenTestMode()
	svc := setupTestService(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ownerAddr := iotago.Ed25519AddressFromPubKey(pub)

	bundleID := "rotate-requires-owner-signature"
	svc.lockedAssets[bundleID] = &LockedAsset{
		ID:           bundleID,
		OwnerAddress: &ownerAddr,
		Status:       AssetStatusLocked,
		CreatedAt:    time.Now().Add(-45 * 24 * time.Hour),
		UpdatedAt:    time.Now().Add(-45 * 24 * time.Hour),
		ShardCount:   3,
	}

	token, err := GenerateAccessToken()
	require.NoError(t, err)

	_, err = svc.RotateKey(context.Background(), &RotateKeyRequest{
		BundleID:    bundleID,
		AccessToken: token,
		Nonce:       newNonceForTest(),
		Signatures:  nil,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "owner signature required")
}

func TestRotateKey_FailClosed_RejectsShortInterval(t *testing.T) {
	ensureTokenTestMode()
	svc := setupTestService(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ownerAddr := iotago.Ed25519AddressFromPubKey(pub)

	bundleID := "rotate-short-interval"
	svc.lockedAssets[bundleID] = &LockedAsset{
		ID:           bundleID,
		OwnerAddress: &ownerAddr,
		Status:       AssetStatusLocked,
		CreatedAt:    time.Now().Add(-12 * time.Hour),
		UpdatedAt:    time.Now().Add(-12 * time.Hour),
		ShardCount:   3,
	}

	token, err := GenerateAccessToken()
	require.NoError(t, err)

	_, err = svc.RotateKey(context.Background(), &RotateKeyRequest{
		BundleID:    bundleID,
		AccessToken: token,
		Nonce:       newNonceForTest(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "rotation interval too short")
}

func TestDeleteKey_FailClosed_RequiresOwnerSignature(t *testing.T) {
	ensureTokenTestMode()
	svc := setupTestService(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ownerAddr := iotago.Ed25519AddressFromPubKey(pub)

	bundleID := "delete-requires-owner-signature"
	svc.lockedAssets[bundleID] = &LockedAsset{
		ID:           bundleID,
		OwnerAddress: &ownerAddr,
		Status:       AssetStatusLocked,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		UpdatedAt:    time.Now().Add(-48 * time.Hour),
		ShardCount:   3,
	}

	token, err := GenerateAccessToken()
	require.NoError(t, err)

	_, err = svc.DeleteKey(context.Background(), &DeleteKeyRequest{
		BundleID:    bundleID,
		AccessToken: token,
		Nonce:       newNonceForTest(),
		Signatures:  nil,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "owner signature required")
}
