package dag_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dueldanov/lockbox/v2/pkg/dag"
	iotago "github.com/iotaledger/iota.go/v3"
)

func TestValidateParents(t *testing.T) {
	parentA := iotago.BlockID{1}
	parentB := iotago.BlockID{2}
	parentC := iotago.BlockID{3}

	err := dag.ValidateParents(iotago.BlockIDs{parentA, parentB, parentC}, 3)
	require.NoError(t, err)

	err = dag.ValidateParents(iotago.BlockIDs{parentA, parentB}, 3)
	require.ErrorIs(t, err, dag.ErrParentsCountInvalid)

	err = dag.ValidateParents(iotago.BlockIDs{parentA, parentA, parentC}, 3)
	require.ErrorIs(t, err, dag.ErrParentsNotUnique)
}
