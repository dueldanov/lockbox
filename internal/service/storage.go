package service

import (
	"encoding/json"
	"fmt"

	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/serializer/v2/marshalutil"
)

const (
	// Storage key prefixes
	StorePrefixLockedAsset     byte = 0
	StorePrefixPendingUnlock   byte = 1
	StorePrefixEmergencyUnlock byte = 2
	StorePrefixMultiSig        byte = 3
)

// StorageManager handles persistence for LockBox
type StorageManager struct {
	store kvstore.KVStore
}

// NewStorageManager creates a new storage manager
func NewStorageManager(store kvstore.KVStore) (*StorageManager, error) {
	lockboxStore, err := store.WithRealm([]byte{0xFF}) // LockBox realm
	if err != nil {
		return nil, err
	}

	return &StorageManager{
		store: lockboxStore,
	}, nil
}

// StoreLockedAsset stores a locked asset
func (sm *StorageManager) StoreLockedAsset(asset *LockedAsset) error {
	key := sm.lockedAssetKey(asset.ID)
	value, err := sm.serializeLockedAsset(asset)
	if err != nil {
		return err
	}

	return sm.store.Set(key, value)
}

// GetLockedAsset retrieves a locked asset
func (sm *StorageManager) GetLockedAsset(assetID string) (*LockedAsset, error) {
	key := sm.lockedAssetKey(assetID)
	value, err := sm.store.Get(key)
	if err != nil {
		return nil, err
	}

	return sm.deserializeLockedAsset(value)
}

// DeleteLockedAsset removes a locked asset
func (sm *StorageManager) DeleteLockedAsset(assetID string) error {
	key := sm.lockedAssetKey(assetID)
	return sm.store.Delete(key)
}

// ListLockedAssets lists all locked assets
func (sm *StorageManager) ListLockedAssets() ([]*LockedAsset, error) {
	var assets []*LockedAsset

	prefix := []byte{StorePrefixLockedAsset}
	if err := sm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
		asset, err := sm.deserializeLockedAsset(value)
		if err != nil {
			return false
		}
		assets = append(assets, asset)
		return true
	}); err != nil {
		return nil, err
	}

	return assets, nil
}

// Helper methods

func (sm *StorageManager) lockedAssetKey(assetID string) []byte {
	ms := marshalutil.New(1 + len(assetID))
	ms.WriteByte(StorePrefixLockedAsset)
	ms.WriteBytes([]byte(assetID))
	return ms.Bytes()
}

func (sm *StorageManager) serializeLockedAsset(asset *LockedAsset) ([]byte, error) {
	// Use JSON for simplicity, could use more efficient serialization
	return json.Marshal(asset)
}

func (sm *StorageManager) deserializeLockedAsset(data []byte) (*LockedAsset, error) {
	var asset LockedAsset
	if err := json.Unmarshal(data, &asset); err != nil {
		return nil, err
	}
	return &asset, nil
}