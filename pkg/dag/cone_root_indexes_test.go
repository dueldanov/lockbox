package dag_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/lockbox/v2/pkg/dag"
	"github.com/iotaledger/lockbox/v2/pkg/model/syncmanager"
	"github.com/iotaledger/lockbox/v2/pkg/testsuite"
	"github.com/iotaledger/lockbox/v2/pkg/whiteflag"
	iotago "github.com/iotaledger/iota.go/v3"
)

const (
	ProtocolVersion = 2
	BelowMaxDepth   = 5
	MinPoWScore     = 10
)

func TestConeRootIndexes(t *testing.T) {

	te := testsuite.SetupTestEnvironment(t, &iotago.Ed25519Address{}, 0, ProtocolVersion, BelowMaxDepth, MinPoWScore, false)
	defer te.CleanupTestEnvironment(true)

	initBlocksCount := 10
	milestonesCount := 30
	minBlocksPerMilestone := 10
	maxBlocksPerMilestone := 100

	_, _ = te.BuildTangle(initBlocksCount, BelowMaxDepth, milestonesCount, minBlocksPerMilestone, maxBlocksPerMilestone, nil,
		func(blockIDs iotago.BlockIDs, blockIDsPerMilestones []iotago.BlockIDs) iotago.BlockIDs {
			return iotago.BlockIDs{blockIDs[len(blockIDs)-1]}
		},
		func(msIndex iotago.MilestoneIndex, blockIDs iotago.BlockIDs, _ *whiteflag.Confirmation, _ *whiteflag.ConfirmedMilestoneStats) {

			latestMilestone := te.Milestones[len(te.Milestones)-1]
			cmi := latestMilestone.Milestone().Index()

			cachedBlockMeta := te.Storage().CachedBlockMetadataOrNil(blockIDs[len(blockIDs)-1]) //nolint:ifshort // false positive

			ycri, ocri, err := dag.ConeRootIndexes(context.Background(), te.Storage(), cachedBlockMeta, cmi)
			require.NoError(te.TestInterface, err)

			minOldestConeRootIndex := iotago.MilestoneIndex(1) // should be 1 if not limited by BelowMaxDepth
			if cmi > syncmanager.MilestoneIndexDelta(BelowMaxDepth) {
				// OCRI should be >=  CMI - BelowMaxDepth
				minOldestConeRootIndex = cmi - syncmanager.MilestoneIndexDelta(BelowMaxDepth)
			}

			// OCRI should be >= min allowed cone root index
			require.GreaterOrEqual(te.TestInterface, ocri, minOldestConeRootIndex)
			// OCRI should be lower or equal to the current confirmed milestone index of that block
			require.LessOrEqual(te.TestInterface, ocri, msIndex)

			// YCRI is the highest referenced index
			// YCRI should be >= min allowed cone root index
			require.GreaterOrEqual(te.TestInterface, ycri, minOldestConeRootIndex)
			// YCRI should be lower or equal to the current confirmed milestone index of that block
			require.LessOrEqual(te.TestInterface, ycri, msIndex)

		},
	)

	// build additional blocks directly referencing the below max depth point

	latestMilestone := te.Milestones[len(te.Milestones)-1]
	cmi := latestMilestone.Milestone().Index()

	// issue block that should be below max depth
	parents := append(latestMilestone.Milestone().Parents(), iotago.EmptyBlockID())
	block := te.NewBlockBuilder("below max depth").Parents(parents.RemoveDupsAndSort()).BuildTaggedData().Store()

	cachedBlockMeta := te.Storage().CachedBlockMetadataOrNil(block.StoredBlockID())
	ycri, ocri, err := dag.ConeRootIndexes(context.Background(), te.Storage(), cachedBlockMeta, cmi)
	require.NoError(te.TestInterface, err)

	// since the block references at least one parent that is below max depth, the whole block should be below max depth and not be picked up by the milestone
	require.Equal(te.TestInterface, iotago.MilestoneIndex(0), ocri)
	require.LessOrEqual(te.TestInterface, ycri, cmi)
}