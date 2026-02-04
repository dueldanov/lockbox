package consensus

import (
	"context"
	"testing"

	"github.com/iotaledger/hive.go/kvstore/mapdb"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/serializer/v2"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/tpkg"
	"github.com/stretchr/testify/require"

	"github.com/dueldanov/lockbox/v2/pkg/model/storage"
	"github.com/dueldanov/lockbox/v2/pkg/protocol"
)

func TestValidateBlockStructureParentsCount(t *testing.T) {
	manager, protoParams := newTestConsensusManager(t)

	tests := []struct {
		name         string
		parentsCount int
		wantErr      error
	}{
		{name: "no parents", parentsCount: 0, wantErr: ErrNoParents},
		{name: "two parents", parentsCount: 2, wantErr: ErrInvalidParentsCount},
		{name: "three parents", parentsCount: 3, wantErr: nil},
		{name: "four parents", parentsCount: 4, wantErr: ErrInvalidParentsCount},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := &iotago.Block{
				ProtocolVersion: protoParams.Version,
				Parents:         tpkg.SortedRandBlockIDs(tt.parentsCount),
			}

			err := manager.validateBlockStructure(block)
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestValidateBlockStructureDuplicateParents(t *testing.T) {
	manager, protoParams := newTestConsensusManager(t)

	parents := tpkg.SortedRandBlockIDs(2)
	parents = append(parents, parents[0]) // duplicate

	block := &iotago.Block{
		ProtocolVersion: protoParams.Version,
		Parents:         parents,
	}

	err := manager.validateBlockStructure(block)
	require.ErrorIs(t, err, ErrDuplicateParents)
}

func newTestConsensusManager(t *testing.T) (*Manager, *iotago.ProtocolParameters) {
	t.Helper()

	tangleStore := mapdb.NewMapDB()
	utxoStore := mapdb.NewMapDB()

	dbStorage, err := storage.New(tangleStore, utxoStore)
	require.NoError(t, err)

	protoParams := tpkg.RandProtocolParameters()
	paramsBytes, err := protoParams.Serialize(serializer.DeSeriModeNoValidation, nil)
	require.NoError(t, err)

	err = dbStorage.ProtocolStorage.StoreProtocolParametersMilestoneOption(&iotago.ProtocolParamsMilestoneOpt{
		TargetMilestoneIndex: 0,
		ProtocolVersion:      protoParams.Version,
		Params:               paramsBytes,
	})
	require.NoError(t, err)

	protoManager, err := protocol.NewManager(dbStorage, 0)
	require.NoError(t, err)

	manager := NewManager(logger.NewNopLogger(), dbStorage, protoManager)
	require.NoError(t, manager.ValidateBlock(context.Background(), &iotago.Block{
		ProtocolVersion: protoParams.Version,
		Parents:         tpkg.SortedRandBlockIDs(3),
	}))

	return manager, protoParams
}
