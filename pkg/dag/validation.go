package dag

import (
	"errors"
	"fmt"

	iotago "github.com/iotaledger/iota.go/v3"
)

var (
	// ErrParentsCountInvalid is returned when the parents count does not match the required amount.
	ErrParentsCountInvalid = errors.New("parents count invalid")
	// ErrParentsNotUnique is returned when duplicate parents are found.
	ErrParentsNotUnique = errors.New("parents not unique")
)

// ValidateParents checks that the parents list matches the required amount and contains no duplicates.
func ValidateParents(parents iotago.BlockIDs, minPreviousRefs int) error {
	if minPreviousRefs <= 0 {
		return fmt.Errorf("%w: minPreviousRefs=%d", ErrParentsCountInvalid, minPreviousRefs)
	}

	if len(parents) != minPreviousRefs {
		return fmt.Errorf("%w: got=%d want=%d", ErrParentsCountInvalid, len(parents), minPreviousRefs)
	}

	seen := make(map[iotago.BlockID]struct{}, len(parents))
	for _, parent := range parents {
		if _, exists := seen[parent]; exists {
			return ErrParentsNotUnique
		}
		seen[parent] = struct{}{}
	}

	return nil
}
