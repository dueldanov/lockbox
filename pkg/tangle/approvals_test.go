package tangle

import (
	"testing"

	"github.com/iotaledger/hive.go/kvstore/mapdb"
	"github.com/iotaledger/hive.go/serializer/v2"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/tpkg"
	"github.com/stretchr/testify/require"

	"github.com/dueldanov/lockbox/v2/pkg/model/storage"
)

func TestUpdateApprovalsForBlockThreshold(t *testing.T) {
	dbStorage, protoParams := newTestTangleStorage(t)

	parentBlock := newTestBlock(t, protoParams, tpkg.SortedRandBlockIDs(1), 0)
	parentID := parentBlock.BlockID()

	tangle := &Tangle{
		storage:            dbStorage,
		minFutureApprovals: 3,
	}

	for i := 1; i <= 3; i++ {
		childBlock := newTestBlock(t, protoParams, iotago.BlockIDs{parentID}, uint64(i))
		cachedChild, _ := dbStorage.StoreBlockIfAbsent(childBlock)
		dbStorage.StoreChild(parentID, childBlock.BlockID()).Release(true)

		tangle.updateApprovalsForBlock(cachedChild)
		cachedChild.Release(true)

		cachedApproval := dbStorage.CachedApprovalStateOrNil(parentID)
		require.NotNil(t, cachedApproval)

		approval := cachedApproval.ApprovalState()
		require.EqualValues(t, uint32(i), approval.ApprovalCount())
		_, confirmed := approval.ConfirmedAt()
		if i < 3 {
			require.False(t, confirmed)
		} else {
			require.True(t, confirmed)
		}

		cachedApproval.Release(true)
	}
}

func newTestTangleStorage(t *testing.T) (*storage.Storage, *iotago.ProtocolParameters) {
	t.Helper()

	tangleStore := mapdb.NewMapDB()
	utxoStore := mapdb.NewMapDB()

	dbStorage, err := storage.New(tangleStore, utxoStore)
	require.NoError(t, err)

	protoParams := tpkg.RandProtocolParameters()

	return dbStorage, protoParams
}

func newTestBlock(t *testing.T, protoParams *iotago.ProtocolParameters, parents iotago.BlockIDs, nonce uint64) *storage.Block {
	t.Helper()

	block := &iotago.Block{
		ProtocolVersion: protoParams.Version,
		Parents:         parents,
		Nonce:           nonce,
	}

	storedBlock, err := storage.NewBlock(block, serializer.DeSeriModeNoValidation, protoParams)
	require.NoError(t, err)

	return storedBlock
}
