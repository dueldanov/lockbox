package storage

import (
	"fmt"
	"time"

	"github.com/iotaledger/hive.go/objectstorage"
	"github.com/iotaledger/hive.go/runtime/syncutils"
	"github.com/iotaledger/hive.go/serializer/v2/marshalutil"
	iotago "github.com/iotaledger/iota.go/v3"
)

// ApprovalState tracks future approvals for a block.
type ApprovalState struct {
	objectstorage.StorableObjectFlags
	syncutils.RWMutex

	blockID iotago.BlockID

	approvalCount   uint32
	firstApprovalAt int64
	confirmedAt     int64
}

// NewApprovalState creates a new ApprovalState for the given block ID.
func NewApprovalState(blockID iotago.BlockID) *ApprovalState {
	return &ApprovalState{
		blockID: blockID,
	}
}

func (a *ApprovalState) BlockID() iotago.BlockID {
	return a.blockID
}

func (a *ApprovalState) ApprovalCount() uint32 {
	a.RLock()
	defer a.RUnlock()

	return a.approvalCount
}

func (a *ApprovalState) FirstApprovalAt() (int64, bool) {
	a.RLock()
	defer a.RUnlock()

	if a.firstApprovalAt == 0 {
		return 0, false
	}

	return a.firstApprovalAt, true
}

func (a *ApprovalState) ConfirmedAt() (int64, bool) {
	a.RLock()
	defer a.RUnlock()

	if a.confirmedAt == 0 {
		return 0, false
	}

	return a.confirmedAt, true
}

// ApplyApproval increments the approval count and sets confirmation timestamps when threshold is reached.
func (a *ApprovalState) ApplyApproval(now time.Time, threshold uint32) (newlyConfirmed bool, firstApprovalAt int64, confirmedAt int64, approvalCount uint32) {
	a.Lock()
	defer a.Unlock()

	nowUnix := now.UnixNano()

	if a.approvalCount == 0 {
		a.firstApprovalAt = nowUnix
	}

	a.approvalCount++

	if a.confirmedAt == 0 && threshold > 0 && a.approvalCount >= threshold {
		a.confirmedAt = nowUnix
		newlyConfirmed = true
	}

	a.SetModified(true)

	return newlyConfirmed, a.firstApprovalAt, a.confirmedAt, a.approvalCount
}

// InitializeFromCount initializes the approval count from existing approvals.
func (a *ApprovalState) InitializeFromCount(count uint32, now time.Time, threshold uint32) (newlyConfirmed bool, firstApprovalAt int64, confirmedAt int64) {
	a.Lock()
	defer a.Unlock()

	if a.approvalCount != 0 {
		return false, a.firstApprovalAt, a.confirmedAt
	}

	a.approvalCount = count
	if count > 0 && a.firstApprovalAt == 0 {
		a.firstApprovalAt = now.UnixNano()
	}

	if a.confirmedAt == 0 && threshold > 0 && count >= threshold {
		a.confirmedAt = now.UnixNano()
		newlyConfirmed = true
	}

	a.SetModified(true)

	return newlyConfirmed, a.firstApprovalAt, a.confirmedAt
}

// ObjectStorage interface.

func (a *ApprovalState) Update(_ objectstorage.StorableObject) {
	panic(fmt.Sprintf("ApprovalState should never be updated: %v", a.blockID.ToHex()))
}

func (a *ApprovalState) ObjectStorageKey() []byte {
	return a.blockID[:]
}

func (a *ApprovalState) ObjectStorageValue() []byte {
	a.RLock()
	defer a.RUnlock()

	/*
		4 bytes uint32 approvalCount
		8 bytes int64  firstApprovalAt (unix nanos)
		8 bytes int64  confirmedAt (unix nanos)
	*/

	marshalUtil := marshalutil.New(4 + 8 + 8)
	marshalUtil.WriteUint32(a.approvalCount)
	marshalUtil.WriteInt64(a.firstApprovalAt)
	marshalUtil.WriteInt64(a.confirmedAt)

	return marshalUtil.Bytes()
}

// ApprovalStateFactory creates ApprovalState from persisted bytes.
func ApprovalStateFactory(key []byte, data []byte) (objectstorage.StorableObject, error) {
	state := &ApprovalState{}
	copy(state.blockID[:], key[:iotago.BlockIDLength])

	marshalUtil := marshalutil.New(data)

	var err error
	state.approvalCount, err = marshalUtil.ReadUint32()
	if err != nil {
		return nil, err
	}

	state.firstApprovalAt, err = marshalUtil.ReadInt64()
	if err != nil {
		return nil, err
	}

	state.confirmedAt, err = marshalUtil.ReadInt64()
	if err != nil {
		return nil, err
	}

	return state, nil
}
