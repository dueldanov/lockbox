package tangle

import (
	"time"

	"github.com/dueldanov/lockbox/v2/pkg/model/storage"
	iotago "github.com/iotaledger/iota.go/v3"
)

func (t *Tangle) updateApprovalsForBlock(cachedBlock *storage.CachedBlock) {
	if t == nil || cachedBlock == nil {
		return
	}
	if t.minFutureApprovals <= 0 {
		return
	}
	if cachedBlock.Block().IsMilestone() {
		return
	}

	parents := cachedBlock.Metadata().Parents()
	if len(parents) == 0 {
		return
	}

	uniqueParents := make(map[iotago.BlockID]struct{}, len(parents))
	for _, parent := range parents {
		uniqueParents[parent] = struct{}{}
	}

	now := time.Now()

	for parentID := range uniqueParents {
		cachedApproval, newlyAdded := t.storage.StoreApprovalStateIfAbsent(parentID) // approval +1
		approvalState := cachedApproval.ApprovalState()

		var newlyConfirmed bool
		var firstApprovalAt int64
		var confirmedAt int64

		if newlyAdded {
			children, err := t.storage.ChildrenBlockIDs(parentID)
			if err == nil {
				newlyConfirmed, firstApprovalAt, confirmedAt = approvalState.InitializeFromCount(uint32(len(children)), now, uint32(t.minFutureApprovals))
			} else {
				newlyConfirmed, firstApprovalAt, confirmedAt, _ = approvalState.ApplyApproval(now, uint32(t.minFutureApprovals))
			}
		} else {
			newlyConfirmed, firstApprovalAt, confirmedAt, _ = approvalState.ApplyApproval(now, uint32(t.minFutureApprovals))
		}

		cachedApproval.Release(true) // approval -1

		if t.serverMetrics == nil {
			continue
		}
		t.serverMetrics.DAGApprovalsAdded.Inc()

		if newlyConfirmed {
			t.serverMetrics.DAGApprovalsConfirmed.Inc()
			if firstApprovalAt > 0 && confirmedAt > 0 {
				latency := time.Duration(confirmedAt-firstApprovalAt) * time.Nanosecond
				if latency < 0 {
					latency = 0
				}
				t.serverMetrics.DAGApprovalLatencyNanos.Store(uint64(latency))
			}
		}
	}
}
