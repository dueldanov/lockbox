package lockbox

import (
    "encoding/json"
    "github.com/iotaledger/hive.go/kvstore"
    "github.com/iotaledger/lockbox/v2/lockbox/lockscript"
)

// Additional storage methods for StorageManager

// StoreScript stores a compiled script
func (sm *StorageManager) StoreScript(scriptID string, script *lockscript.CompiledScript) error {
    key := sm.scriptKey(scriptID)
    value, err := json.Marshal(script)
    if err != nil {
        return err
    }
    return sm.store.Set(key, value)
}

// LoadScripts loads all stored scripts
func (sm *StorageManager) LoadScripts() ([]*lockscript.CompiledScript, error) {
    var scripts []*lockscript.CompiledScript
    
    prefix := []byte{StorePrefixScript}
    if err := sm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
        var script lockscript.CompiledScript
        if err := json.Unmarshal(value, &script); err != nil {
            return false
        }
        scripts = append(scripts, &script)
        return true
    }); err != nil {
        return nil, err
    }
    
    return scripts, nil
}

// StoreMultiSigConfig stores a multi-signature configuration
func (sm *StorageManager) StoreMultiSigConfig(config *MultiSigConfig) error {
    key := sm.multiSigKey(config.ID)
    value, err := json.Marshal(config)
    if err != nil {
        return err
    }
    return sm.store.Set(key, value)
}

// GetMultiSigConfig retrieves a multi-signature configuration
func (sm *StorageManager) GetMultiSigConfig(configID string) (*MultiSigConfig, error) {
    key := sm.multiSigKey(configID)
    value, err := sm.store.Get(key)
    if err != nil {
        return nil, err
    }
    
    var config MultiSigConfig
    if err := json.Unmarshal(value, &config); err != nil {
        return nil, err
    }
    
    return &config, nil
}

// StorePendingUnlock stores a pending unlock request
func (sm *StorageManager) StorePendingUnlock(assetID string, unlockTime int64) error {
    key := sm.pendingUnlockKey(assetID)
    value := make([]byte, 8)
    // Store unlock time as bytes
    for i := 0; i < 8; i++ {
        value[i] = byte(unlockTime >> (8 * (7 - i)))
    }
    return sm.store.Set(key, value)
}

// GetPendingUnlocks retrieves all pending unlocks
func (sm *StorageManager) GetPendingUnlocks() (map[string]int64, error) {
    unlocks := make(map[string]int64)
    
    prefix := []byte{StorePrefixPendingUnlock}
    if err := sm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
        // Extract asset ID from key
        assetID := string(key[1:])
        
        // Extract unlock time from value
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

// Helper methods for key generation

func (sm *StorageManager) scriptKey(scriptID string) []byte {
    return append([]byte{StorePrefixScript}, []byte(scriptID)...)
}

func (sm *StorageManager) multiSigKey(configID string) []byte {
    return append([]byte{StorePrefixMultiSig}, []byte(configID)...)
}

func (sm *StorageManager) pendingUnlockKey(assetID string) []byte {
    return append([]byte{StorePrefixPendingUnlock}, []byte(assetID)...)
}

// Additional storage prefixes
const (
    StorePrefixScript byte = 4
)