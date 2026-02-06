package service

import (
	"fmt"

	iotago "github.com/iotaledger/iota.go/v3"
)

// verifyKeyOperationAuthorization enforces signature-based authorization for key operations.
//
// SECURITY:
// - Multi-sig assets require cryptographic threshold verification.
// - Non-multi-sig assets still require one valid owner signature (fail-closed).
func (s *Service) verifyKeyOperationAuthorization(opName, signingMessage string, signatures [][]byte, asset *LockedAsset) error {
	if asset == nil {
		return fmt.Errorf("asset is required for %s authorization", opName)
	}

	hasMultiSigAddresses := len(asset.MultiSigAddresses) > 0
	hasThreshold := asset.MinSignatures > 0

	switch {
	case hasMultiSigAddresses && hasThreshold:
		if asset.MinSignatures > len(asset.MultiSigAddresses) {
			return fmt.Errorf(
				"invalid multi-sig config: required=%d registered=%d",
				asset.MinSignatures,
				len(asset.MultiSigAddresses),
			)
		}

		if len(signatures) < asset.MinSignatures {
			return fmt.Errorf("insufficient signatures: got %d, need %d", len(signatures), asset.MinSignatures)
		}

		validSigs, err := s.verifyMultiSigSignatures(signingMessage, signatures, asset.MultiSigAddresses)
		if err != nil {
			return fmt.Errorf("multi-sig verification failed: %w", err)
		}
		if validSigs < asset.MinSignatures {
			return fmt.Errorf("insufficient valid signatures: got %d, need %d", validSigs, asset.MinSignatures)
		}
		return nil

	case hasMultiSigAddresses != hasThreshold:
		return fmt.Errorf(
			"invalid multi-sig config: addresses=%d required=%d",
			len(asset.MultiSigAddresses),
			asset.MinSignatures,
		)

	default:
		if asset.OwnerAddress == nil {
			return fmt.Errorf("owner address is required for %s authorization", opName)
		}
		if len(signatures) == 0 {
			return fmt.Errorf("owner signature required for %s", opName)
		}

		validSigs, err := s.verifyMultiSigSignatures(signingMessage, signatures, []iotago.Address{asset.OwnerAddress})
		if err != nil {
			return fmt.Errorf("owner signature verification failed: %w", err)
		}
		if validSigs < 1 {
			return fmt.Errorf("owner signature required for %s", opName)
		}
		return nil
	}
}
