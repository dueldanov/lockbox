package service

import (
	"encoding/json"
	"fmt"
	"hash/crc32"

	"github.com/iotaledger/hive.go/kvstore"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
)

func (sm *StorageManager) StoreScript(scriptID string, script *lockscript.CompiledScript) error {
	key := sm.scriptKey(scriptID)
	value, err := json.Marshal(script)
	if err != nil {
		return err
	}
	// Add integrity check with CRC32
	checksum := crc32.ChecksumIEEE(value)
	checksumKey := sm.scriptChecksumKey(scriptID)
	if err := sm.store.Set(checksumKey, []byte(fmt.Sprintf("%d", checksum))); err != nil {
		return fmt.Errorf("failed to store script checksum: %w", err)
	}
	return sm.store.Set(key, value)
}

func (sm *StorageManager) LoadScripts() ([]*lockscript.CompiledScript, error) {
	var scripts []*lockscript.CompiledScript
	prefix := []byte{StorePrefixScript}
	if err := sm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
		var script lockscript.CompiledScript
		if err := json.Unmarshal(value, &script); err != nil {
			return false
		}
		// Verify integrity
		checksumKey := sm.scriptChecksumKey(string(key[1:]))
		checksumData, err := sm.store.Get(checksumKey)
		if err == nil {
			expectedChecksum := crc32.ChecksumIEEE(value)
			storedChecksum := uint32(0)
			fmt.Sscanf(string(checksumData), "%d", &storedChecksum)
			if expectedChecksum != storedChecksum {
				sm.LogWarnf("Integrity check failed for script %s", string(key[1:]))
				return true // Skip corrupted script but continue
			}
		}
		scripts = append(scripts, &script)
		return true
	}); err != nil {
		return nil, err
	}
	return scripts, nil
}

func (sm *StorageManager) StoreMultiSigConfig(config *MultiSigConfig) error {
	key := sm.multiSigKey(config.ID)
	value, err := json.Marshal(config)
	if err != nil {
		return err
	}
	// Add integrity check with CRC32
	checksum := crc32.ChecksumIEEE(value)
	checksumKey := sm.multiSigChecksumKey(config.ID)
	if err := sm.store.Set(checksumKey, []byte(fmt.Sprintf("%d", checksum))); err != nil {
		return fmt.Errorf("failed to store multi-sig checksum: %w", err)
	}
	return sm.store.Set(key, value)
}

func (sm *StorageManager) GetMultiSigConfig(configID string) (*MultiSigConfig, error) {
	key := sm.multiSigKey(configID)
	value, err := sm.store.Get(key)
	if err != nil {
		return nil, err
	}
	// Verify integrity
	checksumKey := sm.multiSigChecksumKey(configID)
	checksumData, err := sm.store.Get(checksumKey)
	if err == nil {
		expectedChecksum := crc32.ChecksumIEEE(value)
		storedChecksum := uint32(0)
		fmt.Sscanf(string(checksumData), "%d", &storedChecksum)
		if expectedChecksum != storedChecksum {
			return nil, fmt.Errorf("integrity check failed for multi-sig config %s", configID)
		}
	}
	var config MultiSigConfig
	if err := json.Unmarshal(value, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (sm *StorageManager) StorePendingUnlock(assetID string, unlockTime int64) error {
	key := sm.pendingUnlockKey(assetID)
	value := make([]byte, 8)
	for i := 0; i < 8; i++ {
		value[i] = byte(unlockTime >> (8 * (7 - i)))
	}
	// Add integrity check with CRC32
	checksum := crc32.ChecksumIEEE(value)
	checksumKey := sm.pendingUnlockChecksumKey(assetID)
	if err := sm.store.Set(checksumKey, []byte(fmt.Sprintf("%d", checksum))); err != nil {
		return fmt.Errorf("failed to store pending unlock checksum: %w", err)
	}
	return sm.store.Set(key, value)
}

func (sm *StorageManager) GetPendingUnlocks() (map[string]int64, error) {
	unlocks := make(map[string]int64)
	prefix := []byte{StorePrefixPendingUnlock}
	if err := sm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
		assetID := string(key[1:])
		// Verify integrity
		checksumKey := sm.pendingUnlockChecksumKey(assetID)
		checksumData, err := sm.store.Get(checksumKey)
		if err == nil {
			expectedChecksum := crc32.ChecksumIEEE(value)
			storedChecksum := uint32(0)
			fmt.Sscanf(string(checksumData), "%d", &storedChecksum)
			if expectedChecksum != storedChecksum {
				sm.LogWarnf("Integrity check failed for pending unlock %s", assetID)
				return true // Skip corrupted entry
			}
		}
		var unlockTime int64
		for i := 0; i < 8; i++ {
			unlockTime = (unlockTime << 8) | int64(value[i])
		}
		unlocks[assetID] = unlockTime
		return true
	}); err != nil {
		return nil, err
	}
	return unlocks, nil
}

func (sm *StorageManager) scriptKey(scriptID string) []byte {
	return append([]byte{StorePrefixScript}, []byte(scriptID)...)
}

func (sm *StorageManager) multiSigKey(configID string) []byte {
	return append([]byte{StorePrefixMultiSig}, []byte(configID)...)
}

func (sm *StorageManager) pendingUnlockKey(assetID string) []byte {
	return append([]byte{StorePrefixPendingUnlock}, []byte(assetID)...)
}

func (sm *StorageManager) scriptChecksumKey(scriptID string) []byte {
	return append([]byte{StorePrefixScript + 1}, []byte(scriptID)...)
}

func (sm *StorageManager) multiSigChecksumKey(configID string) []byte {
	return append([]byte{StorePrefixMultiSig + 1}, []byte(configID)...)
}

func (sm *StorageManager) pendingUnlockChecksumKey(assetID string) []byte {
	return append([]byte{StorePrefixPendingUnlock + 1}, []byte(assetID)...)
}

const (
	StorePrefixScript byte = 4
)