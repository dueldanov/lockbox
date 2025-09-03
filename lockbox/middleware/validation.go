package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/iotaledger/lockbox/v2/lockbox"
	"github.com/iotaledger/lockbox/v2/lockbox/errors"
	iotago "github.com/iotaledger/iota.go/v3"
)

// ValidationMiddleware provides request validation
type ValidationMiddleware struct {
	next lockbox.Service
}

// NewValidationMiddleware creates validation middleware
func NewValidationMiddleware(next lockbox.Service) *ValidationMiddleware {
	return &ValidationMiddleware{
		next: next,
	}
}

// LockAsset validates and forwards lock asset requests
func (v *ValidationMiddleware) LockAsset(ctx context.Context, req *lockbox.LockAssetRequest) (*lockbox.LockAssetResponse, error) {
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
	if len(req.LockScript) > 65536 {
		return nil, errors.ErrScriptTooLarge(65536)
	}
	
	// Validate multi-sig if present
	if len(req.MultiSigAddresses) > 0 {
		if req.MinSignatures <= 0 {
			return nil, errors.ErrInvalidArgument("minimum signatures must be positive")
		}
		if req.MinSignatures > len(req.MultiSigAddresses) {
			return nil, errors.ErrInvalidArgument("minimum signatures cannot exceed number of addresses")
		}
		if len(req.MultiSigAddresses) > 20 {
			return nil, errors.ErrInvalidArgument("maximum 20 multi-sig addresses allowed")
		}
	}
	
	return v.next.LockAsset(ctx, req)
}

// UnlockAsset validates and forwards unlock asset requests
func (v *ValidationMiddleware) UnlockAsset(ctx context.Context, req *lockbox.UnlockAssetRequest) (*lockbox.UnlockAssetResponse, error) {
	// Validate asset ID
	if req.AssetID == "" {
		return nil, errors.ErrInvalidArgument("asset ID is required")
	}
	
	// Validate asset ID format
	if !isValidAssetID(req.AssetID) {
		return nil, errors.ErrInvalidArgument("invalid asset ID format")
	}
	
	// Validate signatures if present
	if len(req.Signatures) > 20 {
		return nil, errors.ErrInvalidArgument("too many signatures provided")
	}
	
	for i, sig := range req.Signatures {
		if len(sig) == 0 {
			return nil, errors.ErrInvalidArgument(fmt.Sprintf("signature %d is empty", i))
		}
		if len(sig) > 512 {
			return nil, errors.ErrInvalidArgument(fmt.Sprintf("signature %d is too large", i))
		}
	}
	
	return v.next.UnlockAsset(ctx, req)
}

// GetAssetStatus validates and forwards get asset status requests
func (v *ValidationMiddleware) GetAssetStatus(ctx context.Context, assetID string) (*lockbox.LockedAsset, error) {
	// Validate asset ID
	if assetID == "" {
		return nil, errors.ErrInvalidArgument("asset ID is required")
	}
	
	// Validate asset ID format
	if !isValidAssetID(assetID) {
		return nil, errors.ErrInvalidArgument("invalid asset ID format")
	}
	
	return v.next.GetAssetStatus(ctx, assetID)
}

// isValidAssetID validates asset ID format
func isValidAssetID(id string) bool {
	// Asset ID should be alphanumeric with hyphens, 8-64 characters
	if len(id) < 8 || len(id) > 64 {
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

// CompileScript validates and forwards compile script requests
func (v *ValidationMiddleware) CompileScript(ctx context.Context, source string) (*lockscript.CompiledScript, error) {
	// Validate script source
	if source == "" {
		return nil, errors.ErrInvalidArgument("script source is required")
	}
	
	// Check script size
	if len(source) > 65536 {
		return nil, errors.ErrScriptTooLarge(65536)
	}
	
	// Basic syntax validation
	if err := validateScriptSyntax(source); err != nil {
		return nil, errors.ErrInvalidScript(err.Error())
	}
	
	return v.next.CompileScript(ctx, source)
}

// validateScriptSyntax performs basic syntax validation
func validateScriptSyntax(source string) error {
	// Check for dangerous keywords
	dangerousKeywords := []string{
		"eval", "exec", "system", "__import__", "os.", "subprocess",
	}
	
	lowerSource := strings.ToLower(source)
	for _, keyword := range dangerousKeywords {
		if strings.Contains(lowerSource, keyword) {
			return fmt.Errorf("potentially dangerous keyword '%s' detected", keyword)
		}
	}
	
	// Check balanced braces
	braceCount := 0
	for _, r := range source {
		switch r {
		case '{':
			braceCount++
		case '}':
			braceCount--
			if braceCount < 0 {
				return fmt.Errorf("unmatched closing brace")
			}
		}
	}
	if braceCount != 0 {
		return fmt.Errorf("unmatched opening brace")
	}
	
	return nil
}