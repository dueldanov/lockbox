package dag

import (
	"context"
	"math"

	"github.com/pkg/errors"

	"github.com/iotaledger/lockbox/v2/pkg/common"
	"github.com/iotaledger/lockbox/v2/pkg/model/storage"
	iotago "github.com/iotaledger/iota.go/v3"
)

// updateOutdatedConeRootIndexes updates the cone root indexes of the given blocks.
// we have to walk the future cone of these blocks and update the cone root indexes,
// because there could be blocks in the future cone that reference an old cone root index.
func updateOutdatedConeRootIndexes(ctx context.Context, parentsTraverserStorage ParentsTraverserStorage, outdatedBlockIDs iotago.BlockIDs, cmi iotago.MilestoneIndex) error {
	// update the outdated cone root indexes
	for _, outdatedBlockID := range outdatedBlockIDs {
		cachedBlockMeta, err := parentsTraverserStorage.CachedBlockMetadata(outdatedBlockID)
		if err != nil {
			return err
		}

		if cachedBlockMeta == nil {
			panic(common.ErrBlockNotFound)
		}

		// updates the cone root indexes of the outdated block
		if _, _, err := ConeRootIndexes(ctx, parentsTraverserStorage, cachedBlockMeta, cmi); err != nil {
			return err
		}
	}

	return nil
}

// ConeRootIndexes searches for the oldest and newest cone root indexes for a given block.
// if a block references blocks in the past cone that are directly or indirectly referenced by a milestone,
// we have to search for the newest cone root index of all blocks in the past cone.
// if a block references another block in the past cone, that is not referenced by the milestone at all,
// we have to search for the oldest cone root index of all blocks in the past cone.
func ConeRootIndexes(ctx context.Context, parentsTraverserStorage ParentsTraverserStorage, cachedBlockMeta *storage.CachedMetadata, cmi iotago.MilestoneIndex) (youngestConeRootIndex iotago.MilestoneIndex, oldestConeRootIndex iotago.MilestoneIndex, err error) {
	defer cachedBlockMeta.Release(true) // meta -1

	// if the block already contains recent (calculation index matches CMI) information about ycri and ocri, return that info
	ycri, ocri, ci := cachedBlockMeta.Metadata().ConeRootIndexes()
	if ci == cmi {
		return ycri, ocri, nil
	}

	youngestConeRootIndex = 0
	oldestConeRootIndex = math.MaxUint32

	updateIndexes := func(ycri iotago.MilestoneIndex, ocri iotago.MilestoneIndex) {

		if youngestConeRootIndex < ycri {
			youngestConeRootIndex = ycri
		}

		if oldestConeRootIndex > ocri {
			oldestConeRootIndex = ocri
		}
	}

	var outdatedBlockIDs iotago.BlockIDs

	// we pass a special traversal condition and consumer to the traverse function.
	// the startBlockID should only be traversed if the ycri and ocri should be calculated for it.
	// for all other blocks in the past cone, we will only traverse them if they are not referenced yet.
	// if the block was already referenced, we will update the indexes with the cached values.
	// if the block was not referenced yet, we will enqueue it to the outdatedBlockIDs.
	startBlockID := cachedBlockMeta.Metadata().BlockID()
	indexesValid := true
	if err := TraverseParentsOfBlock(
		ctx,
		parentsTraverserStorage,
		cachedBlockMeta.Metadata().BlockID(),
		// traversal condition
		func(cachedBlockMeta *storage.CachedMetadata) (bool, error) { // meta +1
			defer cachedBlockMeta.Release(true) // meta -1

			if referenced, at := cachedBlockMeta.Metadata().ReferencedWithIndex(); referenced {
				// do not traverse referenced blocks
				updateIndexes(at, at)

				return false, nil
			}

			// only traverse the start block ID, the rest of the blocks are traversed but only collected
			if startBlockID == cachedBlockMeta.Metadata().BlockID() {
				return true, nil
			}

			// make sure the block is not collected already
			ycri, ocri, ci := cachedBlockMeta.Metadata().ConeRootIndexes()
			if ci == cmi {
				updateIndexes(ycri, ocri)

				return false, nil
			}

			// collect all blocks that are not referenced yet
			return true, nil
		},
		// consumer (collect unreferenced blocks as outdated)
		func(cachedBlockMeta *storage.CachedMetadata) error { // meta +1
			defer cachedBlockMeta.Release(true) // meta -1

			if startBlockID == cachedBlockMeta.Metadata().BlockID() {
				// skip the requested block ID
				return nil
			}

			outdatedBlockIDs = append(outdatedBlockIDs, cachedBlockMeta.Metadata().BlockID())

			return nil
		},
		// called on missing parents
		nil,
		// called on solid entry points
		func(blockID iotago.BlockID) error {
			entryPointIndex, _, err := parentsTraverserStorage.SolidEntryPointsIndex(blockID)
			if err != nil {
				return err
			}

			updateIndexes(entryPointIndex, entryPointIndex)

			return nil
		},
		// the cone root indexes would not be correct if we would not traverse the solid entry points
		false); err != nil {

		if errors.Is(err, common.ErrBlockNotFound) {
			// one or more parents are not found, so the cone root indexes are not valid
			indexesValid = false
		} else if errors.Is(err, common.ErrOperationAborted) {
			return 0, 0, err
		} else {
			panic(err)
		}
	}

	// update the outdated cone root indexes collected during traversal
	if err := updateOutdatedConeRootIndexes(ctx, parentsTraverserStorage, outdatedBlockIDs, cmi); err != nil {
		return 0, 0, err
	}

	if !indexesValid || oldestConeRootIndex == math.MaxUint32 {
		// block is not solid or references invalid blocks, return zero values. white-flag will not pick it up
		return 0, 0, nil
	}

	// set the computed cone root indexes in the metadata
	cachedBlockMeta.Metadata().SetConeRootIndexes(youngestConeRootIndex, oldestConeRootIndex, cmi)

	return youngestConeRootIndex, oldestConeRootIndex, nil
}

// UpdateConeRootIndexes updates the cone root indexes of the future cone of all given blocks.
// all the blocks are traversed, and their future cone (blocks approving the given blocks) get updated.
func UpdateConeRootIndexes(ctx context.Context, traverserStorage TraverserStorage, blockIDs iotago.BlockIDs, cmi iotago.MilestoneIndex) error {
	traversed := map[iotago.BlockID]struct{}{}
	t := NewChildrenTraverser(traverserStorage)

	for _, blockID := range blockIDs {
		if err := t.Traverse(
			ctx,
			blockID,
			// traversal condition
			func(cachedBlockMeta *storage.CachedMetadata) (bool, error) { // meta +1
				defer cachedBlockMeta.Release(true) // meta -1

				// only traverse and update if the block was not traversed before and is solid
				_, previouslyTraversed := traversed[cachedBlockMeta.Metadata().BlockID()]

				return !previouslyTraversed && cachedBlockMeta.Metadata().IsSolid(), nil
			},
			// consumer
			func(cachedBlockMeta *storage.CachedMetadata) error { // meta +1
				defer cachedBlockMeta.Release(true) // meta -1

				traversed[cachedBlockMeta.Metadata().BlockID()] = struct{}{}

				if _, _, err := ConeRootIndexes(ctx, traverserStorage, cachedBlockMeta.Retain(), cmi); err != nil {
					return err
				}

				return nil
			},
			// called on missing parents
			// skip non-solid blocks
			false); err != nil {
			return err
		}
	}

	return nil
}