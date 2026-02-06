package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/errors"
	"github.com/dueldanov/lockbox/v2/internal/service"
	iotago "github.com/iotaledger/iota.go/v3"
)

// Validation limits
const (
	maxScriptSize      = 65536 // Maximum LockScript source size in bytes
	maxMultiSigAddrs   = 20    // Maximum number of multi-sig addresses
	maxSignatureSize   = 512   // Maximum individual signature size in bytes
	maxSignatureCount  = 20    // Maximum number of signatures per request
	minAssetIDLength   = 8     // Minimum asset ID length
	maxAssetIDLength   = 64    // Maximum asset ID length
)

// ValidationMiddleware provides request validation
type ValidationMiddleware struct {
	next Service
}

// NewValidationMiddleware creates validation middleware
func NewValidationMiddleware(next Service) *ValidationMiddleware {
	return &ValidationMiddleware{
		next: next,
	}
}

// LockAsset validates and forwards lock asset requests
func (v *ValidationMiddleware) LockAsset(ctx context.Context, req *service.LockAssetRequest) (*service.LockAssetResponse, error) {
	// Validate owner address
	if req.OwnerAddress == nil {
		return nil, errors.ErrInvalidArgument("owner address is required")
	}
	
	// Validate output ID
	if req.OutputID == (iotago.OutputID{}) {
		return nil, errors.ErrInvalidArgument("output ID is required")
	}
	
	// Validate lock duration
	if req.LockDuration < time.Hour {
		return nil, errors.ErrInvalidArgument("lock duration must be at least 1 hour")
	}
	if req.LockDuration > 100*365*24*time.Hour {
		return nil, errors.ErrInvalidArgument("lock duration cannot exceed 100 years")
	}
	
	// Validate lock script
	if len(req.LockScript) > maxScriptSize {
		return nil, errors.ErrScriptTooLarge(maxScriptSize)
	}

	// Validate multi-sig if present
	if len(req.MultiSigAddresses) > 0 {
		if req.MinSignatures <= 0 {
			return nil, errors.ErrInvalidArgument("minimum signatures must be positive")
		}
		if req.MinSignatures > len(req.MultiSigAddresses) {
			return nil, errors.ErrInvalidArgument("minimum signatures cannot exceed number of addresses")
		}
		if len(req.MultiSigAddresses) > maxMultiSigAddrs {
			return nil, errors.ErrInvalidArgument(fmt.Sprintf("maximum %d multi-sig addresses allowed", maxMultiSigAddrs))
		}
	}
	
	return v.next.LockAsset(ctx, req)
}

// UnlockAsset validates and forwards unlock asset requests
func (v *ValidationMiddleware) UnlockAsset(ctx context.Context, req *service.UnlockAssetRequest) (*service.UnlockAssetResponse, error) {
	// Validate asset ID
	if req.AssetID == "" {
		return nil, errors.ErrInvalidArgument("asset ID is required")
	}
	
	// Validate asset ID format
	if !isValidAssetID(req.AssetID) {
		return nil, errors.ErrInvalidArgument("invalid asset ID format")
	}
	
	// Validate signatures if present
	if len(req.Signatures) > maxSignatureCount {
		return nil, errors.ErrInvalidArgument("too many signatures provided")
	}

	for i, sig := range req.Signatures {
		if len(sig) == 0 {
			return nil, errors.ErrInvalidArgument(fmt.Sprintf("signature %d is empty", i))
		}
		if len(sig) > maxSignatureSize {
			return nil, errors.ErrInvalidArgument(fmt.Sprintf("signature %d is too large", i))
		}
	}
	
	return v.next.UnlockAsset(ctx, req)
}

// GetAssetStatus validates and forwards get asset status requests
func (v *ValidationMiddleware) GetAssetStatus(assetID string) (*service.LockedAsset, error) {
	// Validate asset ID
	if assetID == "" {
		return nil, errors.ErrInvalidArgument("asset ID is required")
	}

	// Validate asset ID format
	if !isValidAssetID(assetID) {
		return nil, errors.ErrInvalidArgument("invalid asset ID format")
	}

	return v.next.GetAssetStatus(assetID)
}

// isValidAssetID validates asset ID format
func isValidAssetID(id string) bool {
	// Asset ID should be alphanumeric with hyphens
	if len(id) < minAssetIDLength || len(id) > maxAssetIDLength {
		return false
	}
	
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	
	// Should not start or end with hyphen
	if strings.HasPrefix(id, "-") || strings.HasSuffix(id, "-") {
		return false
	}
	
	return true
}

