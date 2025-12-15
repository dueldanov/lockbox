package lockscript

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVerifyEd25519Signature_Valid(t *testing.T) {
	// Generate a key pair
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Sign a message
	message := "Hello, LockBox!"
	signatureHex := SignMessage(privKey, message)

	// Verify the signature
	verified, err := VerifyEd25519Signature(pubKeyHex, message, signatureHex)
	if err != nil {
		t.Fatalf("VerifyEd25519Signature failed: %v", err)
	}
	if !verified {
		t.Error("expected signature to be valid, got invalid")
	}
}

func TestVerifyEd25519Signature_WrongSignature(t *testing.T) {
	pubKeyHex, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := "Hello, LockBox!"
	// Use a fake signature (64 bytes of zeros)
	fakeSignatureHex := strings.Repeat("00", 64)

	verified, err := VerifyEd25519Signature(pubKeyHex, message, fakeSignatureHex)
	if err != nil {
		t.Fatalf("VerifyEd25519Signature failed: %v", err)
	}
	if verified {
		t.Error("expected signature to be invalid, got valid")
	}
}

func TestVerifyEd25519Signature_WrongPublicKey(t *testing.T) {
	// Generate two different key pairs
	_, privKey1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubKeyHex2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Sign with key1, verify with key2
	message := "Hello, LockBox!"
	signatureHex := SignMessage(privKey1, message)

	verified, err := VerifyEd25519Signature(pubKeyHex2, message, signatureHex)
	if err != nil {
		t.Fatalf("VerifyEd25519Signature failed: %v", err)
	}
	if verified {
		t.Error("expected signature to be invalid with wrong key, got valid")
	}
}

func TestVerifyEd25519Signature_ModifiedMessage(t *testing.T) {
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	originalMessage := "Hello, LockBox!"
	signatureHex := SignMessage(privKey, originalMessage)

	// Try to verify with modified message
	modifiedMessage := "Hello, Modified!"
	verified, err := VerifyEd25519Signature(pubKeyHex, modifiedMessage, signatureHex)
	if err != nil {
		t.Fatalf("VerifyEd25519Signature failed: %v", err)
	}
	if verified {
		t.Error("expected signature to be invalid with modified message, got valid")
	}
}

func TestVerifyEd25519Signature_InvalidPubKeyHex(t *testing.T) {
	tests := []struct {
		name      string
		pubKeyHex string
	}{
		{"invalid hex chars", "zzzz"},
		{"odd length hex", "abc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyEd25519Signature(tc.pubKeyHex, "message", strings.Repeat("00", 64))
			if err == nil {
				t.Error("expected error for invalid pubkey hex, got nil")
			}
			if err != ErrInvalidHex {
				t.Errorf("expected ErrInvalidHex, got %v", err)
			}
		})
	}
}

func TestVerifyEd25519Signature_InvalidPubKeySize(t *testing.T) {
	tests := []struct {
		name      string
		pubKeyHex string
	}{
		{"too short (31 bytes)", strings.Repeat("aa", 31)},
		{"too long (33 bytes)", strings.Repeat("aa", 33)},
		{"empty", ""},
		{"one byte", "aa"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyEd25519Signature(tc.pubKeyHex, "message", strings.Repeat("00", 64))
			if err == nil {
				t.Error("expected error for invalid pubkey size, got nil")
			}
			if err != ErrInvalidPublicKeySize {
				t.Errorf("expected ErrInvalidPublicKeySize, got %v", err)
			}
		})
	}
}

func TestVerifyEd25519Signature_InvalidSignatureHex(t *testing.T) {
	validPubKey := strings.Repeat("aa", 32)

	tests := []struct {
		name         string
		signatureHex string
	}{
		{"invalid hex chars", "zzzz"},
		{"odd length hex", "abc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyEd25519Signature(validPubKey, "message", tc.signatureHex)
			if err == nil {
				t.Error("expected error for invalid signature hex, got nil")
			}
			if err != ErrInvalidHex {
				t.Errorf("expected ErrInvalidHex, got %v", err)
			}
		})
	}
}

func TestVerifyEd25519Signature_InvalidSignatureSize(t *testing.T) {
	validPubKey := strings.Repeat("aa", 32)

	tests := []struct {
		name         string
		signatureHex string
	}{
		{"too short (63 bytes)", strings.Repeat("00", 63)},
		{"too long (65 bytes)", strings.Repeat("00", 65)},
		{"empty", ""},
		{"one byte", "00"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyEd25519Signature(validPubKey, "message", tc.signatureHex)
			if err == nil {
				t.Error("expected error for invalid signature size, got nil")
			}
			if err != ErrInvalidSignatureSize {
				t.Errorf("expected ErrInvalidSignatureSize, got %v", err)
			}
		})
	}
}

func TestSignMessage(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := "Test message"
	signatureHex := SignMessage(privKey, message)

	// Verify signature is 64 bytes (128 hex chars)
	if len(signatureHex) != 128 {
		t.Errorf("signature hex length: got %d, want 128", len(signatureHex))
	}

	// Verify it's valid hex
	_, err = hex.DecodeString(signatureHex)
	if err != nil {
		t.Errorf("signature is not valid hex: %v", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Public key should be 32 bytes (64 hex chars)
	if len(pubKeyHex) != 64 {
		t.Errorf("public key hex length: got %d, want 64", len(pubKeyHex))
	}

	// Private key should be 64 bytes
	if len(privKey) != ed25519.PrivateKeySize {
		t.Errorf("private key length: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}

	// Keys should be valid - sign and verify
	message := "test"
	sig := SignMessage(privKey, message)
	verified, err := VerifyEd25519Signature(pubKeyHex, message, sig)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if !verified {
		t.Error("generated keys don't work together")
	}
}

func TestPublicKeyHex(t *testing.T) {
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// PublicKeyHex should return the same public key
	extractedPubKey := PublicKeyHex(privKey)
	if extractedPubKey != pubKeyHex {
		t.Errorf("PublicKeyHex mismatch: got %s, want %s", extractedPubKey, pubKeyHex)
	}
}

func TestVerifyEd25519Signature_EmptyMessage(t *testing.T) {
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Empty message should still work
	message := ""
	signatureHex := SignMessage(privKey, message)

	verified, err := VerifyEd25519Signature(pubKeyHex, message, signatureHex)
	if err != nil {
		t.Fatalf("VerifyEd25519Signature failed: %v", err)
	}
	if !verified {
		t.Error("expected valid signature for empty message")
	}
}

func TestVerifyEd25519Signature_LongMessage(t *testing.T) {
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Long message
	message := strings.Repeat("A", 10000)
	signatureHex := SignMessage(privKey, message)

	verified, err := VerifyEd25519Signature(pubKeyHex, message, signatureHex)
	if err != nil {
		t.Fatalf("VerifyEd25519Signature failed: %v", err)
	}
	if !verified {
		t.Error("expected valid signature for long message")
	}
}

func TestVerifyEd25519Signature_SpecialCharsMessage(t *testing.T) {
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Message with special characters and unicode
	message := "Hello! @#$%^&*() \n\t\r 你好 🔐"
	signatureHex := SignMessage(privKey, message)

	verified, err := VerifyEd25519Signature(pubKeyHex, message, signatureHex)
	if err != nil {
		t.Fatalf("VerifyEd25519Signature failed: %v", err)
	}
	if !verified {
		t.Error("expected valid signature for message with special chars")
	}
}

// Note: TestVMVerifySignature is commented out until the lockscript VM compilation issues are fixed
// The VM integration uses VerifyEd25519Signature internally, which is tested above.
// When the VM compiles, this test should verify end-to-end integration.

// func TestVMVerifySignature(t *testing.T) {
// 	vm := NewVirtualMachine()
// 	pubKeyHex, privKey, err := GenerateKeyPair()
// 	if err != nil {
// 		t.Fatalf("GenerateKeyPair failed: %v", err)
// 	}
// 	message := "unlock_asset_12345"
// 	signatureHex := SignMessage(privKey, message)
// 	if !vm.verifySignature(pubKeyHex, message, signatureHex) {
// 		t.Error("VM.verifySignature should return true for valid signature")
// 	}
// }
