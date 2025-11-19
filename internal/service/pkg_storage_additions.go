package service

import (
	"encoding/json"
	"fmt"
	
	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/serializer/v2/marshalutil"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
)

const (
	StorePrefixScript       byte = 4
	StorePrefixVerification byte = 5
	StorePrefixVault        byte = 6
)

// Script storage methods
func (sm *StorageManager) StoreScript(scriptID string, script *lockscript.CompiledScript) error {
	key := sm.scriptKey(scriptID)
	value, err := json.Marshal(script)
	if err != nil {
		return fmt.Errorf("failed to marshal script: %w", err)
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
		scripts = append(scripts, &script)
		return true
	}); err != nil {
		return nil, fmt.Errorf("failed to iterate scripts: %w", err)
	}
	
	return scripts, nil
}

func (sm *StorageManager) GetScript(scriptID string) (*lockscript.CompiledScript, error) {
	key := sm.scriptKey(scriptID)
	value, err := sm.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("script not found: %w", err)
	}
	
	var script lockscript.CompiledScript
	if err := json.Unmarshal(value, &script); err != nil {
		return nil, fmt.Errorf("failed to unmarshal script: %w", err)
	}
	
	return &script, nil
}

// Multi-signature storage methods
func (sm *StorageManager) StoreMultiSigConfig(config *MultiSigConfig) error {
	key := sm.multiSigKey(config.ID)
	value, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal multi-sig config: %w", err)
	}
	return sm.store.Set(key, value)
}

func (sm *StorageManager) GetMultiSigConfig(configID string) (*MultiSigConfig, error) {
	key := sm.multiSigKey(configID)
	value, err := sm.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("multi-sig config not found: %w", err)
	}
	
	var config MultiSigConfig
	if err := json.Unmarshal(value, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal multi-sig config: %w", err)
	}
	
	return &config, nil
}

// Pending unlock storage methods
func (sm *StorageManager) StorePendingUnlock(assetID string, unlockTime int64) error {
	key := sm.pendingUnlockKey(assetID)
	value := make([]byte, 8)
	for i := 0; i < 8; i++ {
		value[i] = byte(unlockTime >> (8 * (7 - i)))
	}
	return sm.store.Set(key, value)
}

func (sm *StorageManager) GetPendingUnlocks() (map[string]int64, error) {
	unlocks := make(map[string]int64)
	prefix := []byte{StorePrefixPendingUnlock}
	
	if err := sm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
		assetID := string(key[1:])
		var unlockTime int64
		for i := 0; i < 8; i++ {
			unlockTime = (unlockTime << 8) | int64(value[i])
		}
		unlocks[assetID] = unlockTime
		return true
	}); err != nil {
		return nil, fmt.Errorf("failed to iterate pending unlocks: %w", err)
	}
	
	return unlocks, nil
}

func (sm *StorageManager) DeletePendingUnlock(assetID string) error {
	key := sm.pendingUnlockKey(assetID)
	return sm.store.Delete(key)
}

// Verification storage methods
func (sm *StorageManager) StoreVerificationResult(assetID string, result *VerificationResult) error {
	key := sm.verificationKey(assetID)
	value, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal verification result: %w", err)
	}
	return sm.store.Set(key, value)
}

func (sm *StorageManager) GetVerificationResult(assetID string) (*VerificationResult, error) {
	key := sm.verificationKey(assetID)
	value, err := sm.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("verification result not found: %w", err)
	}
	
	var result VerificationResult
	if err := json.Unmarshal(value, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verification result: %w", err)
	}
	
	return &result, nil
}

// Vault storage methods
func (sm *StorageManager) StoreVaultInfo(vault *VaultInfo) error {
	key := sm.vaultKey(vault.ID)
	value, err := json.Marshal(vault)
	if err != nil {
		return fmt.Errorf("failed to marshal vault info: %w", err)
	}
	return sm.store.Set(key, value)
}

func (sm *StorageManager) GetVaultInfo(vaultID string) (*VaultInfo, error) {
	key := sm.vaultKey(vaultID)
	value, err := sm.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("vault info not found: %w", err)
	}
	
	var vault VaultInfo
	if err := json.Unmarshal(value, &vault); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault info: %w", err)
	}
	
	return &vault, nil
}

// Key generation methods
func (sm *StorageManager) scriptKey(scriptID string) []byte {
	ms := marshalutil.New(1 + len(scriptID))
	ms.WriteByte(StorePrefixScript)
	ms.WriteBytes([]byte(scriptID))
	return ms.Bytes()
}

func (sm *StorageManager) multiSigKey(configID string) []byte {
	ms := marshalutil.New(1 + len(configID))
	ms.WriteByte(StorePrefixMultiSig)
	ms.WriteBytes([]byte(configID))
	return ms.Bytes()
}

func (sm *StorageManager) pendingUnlockKey(assetID string) []byte {
	ms := marshalutil.New(1 + len(assetID))
	ms.WriteByte(StorePrefixPendingUnlock)
	ms.WriteBytes([]byte(assetID))
	return ms.Bytes()
}

func (sm *StorageManager) verificationKey(assetID string) []byte {
	ms := marshalutil.New(1 + len(assetID))
	ms.WriteByte(StorePrefixVerification)
	ms.WriteBytes([]byte(assetID))
	return ms.Bytes()
}

func (sm *StorageManager) vaultKey(vaultID string) []byte {
	ms := marshalutil.New(1 + len(vaultID))
	ms.WriteByte(StorePrefixVault)
	ms.WriteBytes([]byte(vaultID))
	return ms.Bytes()
}

// VerificationResult struct for storage
type VerificationResult struct {
	AssetID    string    `json:"asset_id"`
	Valid      bool      `json:"valid"`
	Timestamp  time.Time `json:"timestamp"`
	NodeID     string    `json:"node_id"`
	Signature  []byte    `json:"signature"`
}