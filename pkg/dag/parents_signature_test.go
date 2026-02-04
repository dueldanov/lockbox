package dag

import (
	"testing"

	"github.com/stretchr/testify/require"

	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/tpkg"
)

func TestValidateParentsSignatureTransaction(t *testing.T) {
	parents := tpkg.SortedRandBlockIDs(3)
	block := &iotago.Block{
		Parents: parents,
		Payload: &iotago.Transaction{
			Essence: iotago.TransactionEssence{
				Payload: ParentsSignatureTaggedData(parents),
			},
		},
	}

	require.NoError(t, ValidateParentsSignature(block))
}

func TestValidateParentsSignatureMissing(t *testing.T) {
	block := &iotago.Block{
		Parents: tpkg.SortedRandBlockIDs(3),
		Payload: &iotago.Transaction{},
	}

	require.ErrorIs(t, ValidateParentsSignature(block), ErrParentsSignatureMissing)
}

func TestValidateParentsSignatureMismatch(t *testing.T) {
	parents := tpkg.SortedRandBlockIDs(3)
	tagged := ParentsSignatureTaggedData(parents)
	tagged.Data[0] ^= 0xFF

	block := &iotago.Block{
		Parents: parents,
		Payload: &iotago.Transaction{
			Essence: iotago.TransactionEssence{
				Payload: tagged,
			},
		},
	}

	require.ErrorIs(t, ValidateParentsSignature(block), ErrParentsSignatureMismatch)
}

func TestValidateParentsSignatureNonTransaction(t *testing.T) {
	block := &iotago.Block{
		Parents: tpkg.SortedRandBlockIDs(3),
		Payload: &iotago.TaggedData{Tag: []byte("demo"), Data: []byte("data")},
	}

	require.NoError(t, ValidateParentsSignature(block))
}
