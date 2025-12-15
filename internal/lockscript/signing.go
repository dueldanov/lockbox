package lockscript

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	// ErrInvalidPublicKeySize indicates the public key is not 32 bytes
	ErrInvalidPublicKeySize = errors.New("invalid Ed25519 public key size: expected 32 bytes")
	// ErrInvalidSignatureSize indicates the signature is not 64 bytes
	ErrInvalidSignatureSize = errors.New("invalid Ed25519 signature size: expected 64 bytes")
	// ErrInvalidHex indicates the hex string could not be decoded
	ErrInvalidHex = errors.New("invalid hex encoding")
)

// VerifyEd25519Signature verifies an Ed25519 signature.
// pubKeyHex: hex-encoded 32-byte public key
// message: the message that was signed (as plaintext string)
// signatureHex: hex-encoded 64-byte signature
func VerifyEd25519Signature(pubKeyHex, message, signatureHex string) (bool, error) {
	// Decode public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, ErrInvalidHex
	}

	// Validate Ed25519 public key size (32 bytes)
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, ErrInvalidPublicKeySize
	}

	// Decode signature from hex
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, ErrInvalidHex
	}

	// Validate Ed25519 signature size (64 bytes)
	if len(signatureBytes) != ed25519.SignatureSize {
		return false, ErrInvalidSignatureSize
	}

	// Verify the signature
	return ed25519.Verify(pubKeyBytes, []byte(message), signatureBytes), nil
}

// SignMessage signs a message using Ed25519 and returns the hex-encoded signature.
// This is primarily useful for testing.
func SignMessage(privateKey ed25519.PrivateKey, message string) string {
	signature := ed25519.Sign(privateKey, []byte(message))
	return hex.EncodeToString(signature)
}

// GenerateKeyPair generates a new Ed25519 key pair.
// Returns hex-encoded public key and the private key.
// This is primarily useful for testing.
func GenerateKeyPair() (pubKeyHex string, privKey ed25519.PrivateKey, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(pubKey), privKey, nil
}

// PublicKeyHex returns the hex-encoded public key from a private key.
// This is useful when you need to extract the public key from a generated keypair.
func PublicKeyHex(privateKey ed25519.PrivateKey) string {
	pubKey := privateKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pubKey)
}
