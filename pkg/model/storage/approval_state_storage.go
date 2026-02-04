package storage

import (
	"time"

	"github.com/dueldanov/lockbox/v2/pkg/common"
	"github.com/dueldanov/lockbox/v2/pkg/profile"
	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/objectstorage"
	iotago "github.com/iotaledger/iota.go/v3"
)

// CachedApprovalState represents a cached ApprovalState.
type CachedApprovalState struct {
	objectstorage.CachedObject
}

// ApprovalState retrieves the approval state cached in this container.
func (c *CachedApprovalState) ApprovalState() *ApprovalState {
	//nolint:forcetypeassert // we will replace that with generics anyway
	return c.Get().(*ApprovalState)
}

// Retain registers a new consumer for the cached approval state.
// approvalState +1.
func (c *CachedApprovalState) Retain() *CachedApprovalState {
	return &CachedApprovalState{CachedObject: c.CachedObject.Retain()} // approvalState +1
}

// ConsumeApprovalState consumes the approval state.
// approvalState -1.
func (c *CachedApprovalState) ConsumeApprovalState(consumer func(*ApprovalState)) {
	c.Consume(func(object objectstorage.StorableObject) { // approvalState -1
		//nolint:forcetypeassert // we will replace that with generics anyway
		consumer(object.(*ApprovalState))
	}, true)
}

func (s *Storage) ApprovalStateStorageSize() int {
	return s.approvalStateStorage.GetSize()
}

func (s *Storage) configureApprovalStateStorage(store kvstore.KVStore, opts *profile.CacheOpts) error {
	cacheTime, err := time.ParseDuration(opts.CacheTime)
	if err != nil {
		return err
	}

	leakDetectionMaxConsumerHoldTime, err := time.ParseDuration(opts.LeakDetectionOptions.MaxConsumerHoldTime)
	if err != nil {
		return err
	}

	approvalStore, err := store.WithRealm([]byte{common.StorePrefixApprovals})
	if err != nil {
		return err
	}

	s.approvalStateStorage = objectstorage.New(
		approvalStore,
		ApprovalStateFactory,
		objectstorage.CacheTime(cacheTime),
		objectstorage.PersistenceEnabled(true),
		objectstorage.StoreOnCreation(true),
		objectstorage.ReleaseExecutorWorkerCount(opts.ReleaseExecutorWorkerCount),
		objectstorage.LeakDetectionEnabled(opts.LeakDetectionOptions.Enabled,
			objectstorage.LeakDetectionOptions{
				MaxConsumersPerObject: opts.LeakDetectionOptions.MaxConsumersPerObject,
				MaxConsumerHoldTime:   leakDetectionMaxConsumerHoldTime,
			}),
	)

	return nil
}

// CachedApprovalStateOrNil returns a cached approval state object.
// approvalState +1.
func (s *Storage) CachedApprovalStateOrNil(blockID iotago.BlockID) *CachedApprovalState {
	cachedApproval := s.approvalStateStorage.Load(blockID[:]) // approvalState +1
	if !cachedApproval.Exists() {
		cachedApproval.Release(true) // approvalState -1

		return nil
	}

	return &CachedApprovalState{CachedObject: cachedApproval}
}

// CachedApprovalState returns a cached approval state object.
// approvalState +1.
func (s *Storage) CachedApprovalState(blockID iotago.BlockID) (*CachedApprovalState, error) {
	return s.CachedApprovalStateOrNil(blockID), nil
}

// StoreApprovalStateIfAbsent returns a cached object and stores the approval state if it was absent.
// approvalState +1.
func (s *Storage) StoreApprovalStateIfAbsent(blockID iotago.BlockID) (cachedApprovalState *CachedApprovalState, newlyAdded bool) {
	cachedApproval := s.approvalStateStorage.ComputeIfAbsent(blockID[:], func(_ []byte) objectstorage.StorableObject { // approvalState +1
		newlyAdded = true

		return NewApprovalState(blockID)
	})

	return &CachedApprovalState{CachedObject: cachedApproval}, newlyAdded
}

// ShutdownApprovalStateStorage shuts down the approval state storage.
func (s *Storage) ShutdownApprovalStateStorage() {
	s.approvalStateStorage.Shutdown()
}

// FlushApprovalStateStorage flushes the approval state storage.
func (s *Storage) FlushApprovalStateStorage() {
	s.approvalStateStorage.Flush()
}
