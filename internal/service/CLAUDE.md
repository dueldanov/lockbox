# Модуль: service

## Назначение

Главная бизнес-логика LockBox:
- LockAsset / UnlockAsset
- GetAssetStatus / ListAssets
- CreateMultiSig / EmergencyUnlock
- Tier capabilities

## Файлы

| Файл | Назначение |
|------|------------|
| `service.go` | Главная логика Lock/Unlock |
| `types.go` | Request/Response типы |
| `tier.go` | TierCapabilities |
| `storage.go` | StorageManager |
| `grpc_server.go` | gRPC endpoints |

## Ключевые типы

```go
// Service главный сервис LockBox
type Service struct {
    *logger.WrappedLogger

    storage         *storage.Storage
    config          *ServiceConfig
    storageManager  *StorageManager

    // Crypto
    shardEncryptor  *crypto.ShardEncryptor
    zkpManager      *crypto.ZKPManager
    zkpProvider     interfaces.ZKPProvider
    hkdfManager     *crypto.HKDFManager
    decoyGenerator  *crypto.DecoyGenerator
    shardMixer      *crypto.ShardMixer

    // Verification
    verifier        *verification.Verifier
    nodeSelector    *verification.NodeSelector
    tokenManager    *verification.TokenManager
    retryManager    *verification.RetryManager
    rateLimiter     *verification.RateLimiter

    // Payment
    paymentProcessor *payment.PaymentProcessor

    // State
    lockedAssets    map[string]*LockedAsset
    pendingUnlocks  map[string]time.Time
    scriptCompiler  interface{} // *lockscript.Engine (initialized in NewService)
}

// ServiceConfig конфигурация сервиса
type ServiceConfig struct {
    Tier                  Tier
    DataDir               string
    MinLockPeriod         time.Duration
    MaxLockPeriod         time.Duration
    EnableEmergencyUnlock bool
    EmergencyDelayDays    int
    MultiSigRequired      bool
    MinMultiSigSigners    int
}

// TierCapabilities возможности тира
type TierCapabilities struct {
    ShardCopies        int     // 3/5/7/10
    DecoyRatio         float64 // 0.5/1.0/1.5/2.0
    MetadataDecoyRatio float64 // 0/0/1.0/2.0
    MultiSigSupported  bool
    EmergencyUnlock    bool
    ScriptComplexity   int
}
```

## API методы

### LockAsset

```go
func (s *Service) LockAsset(ctx context.Context, req *LockAssetRequest) (*LockAssetResponse, error)
```

**Реализовано:**
1. ✅ Валидация duration
2. ✅ Валидация LockScript (компиляция при Lock для раннего обнаружения ошибок)
3. ✅ Генерация assetID
4. ✅ Создание ownership proof (ZKP Groth16)
5. ✅ HKDF key derivation
6. ✅ XChaCha20-Poly1305 шифрование (V2 format)
7. ✅ DecoyGenerator — генерация decoy shards по tier ratio
8. ✅ ShardMixer — перемешивание real + decoy shards
9. ✅ Tier-based redundant copies (ShardCopies копий каждого шарда)
10. ✅ Metadata decoys (Premium/Elite)
11. ✅ Сохранение asset в storage

**Остаётся (TODO):**
- ❌ Geo-distribution (шарды хранятся локально)

### UnlockAsset

```go
func (s *Service) UnlockAsset(ctx context.Context, req *UnlockAssetRequest) (*UnlockAssetResponse, error)
```

**Реализовано:**
1. ✅ Получение asset
2. ✅ Проверка unlock time
3. ✅ Верификация ownership proof (ZKP)
4. ✅ Multi-sig проверка подписей
5. ✅ Исполнение LockScript условий
6. ✅ Trial decryption для восстановления real shards (V2)
7. ✅ Расшифровка шардов

## Tier Capabilities

```go
caps := GetCapabilities(TierStandard)

// Basic:    ShardCopies=3,  DecoyRatio=0.5, MultiSig=false, ScriptComplexity=1
// Standard: ShardCopies=5,  DecoyRatio=1.0, MultiSig=true,  ScriptComplexity=2
// Premium:  ShardCopies=7,  DecoyRatio=1.5, MultiSig=true,  ScriptComplexity=3
// Elite:    ShardCopies=10, DecoyRatio=2.0, MultiSig=true,  ScriptComplexity=4
```

## Паттерны использования

### Создание сервиса

```go
config := &ServiceConfig{
    Tier:          TierStandard,
    DataDir:       "/var/lockbox",
    MinLockPeriod: time.Hour,
    MaxLockPeriod: 365 * 24 * time.Hour,
}

svc, err := NewService(
    log,
    storage,
    utxoManager,
    syncManager,
    protocolManager,
    config,
)
// NewService automatically calls InitializeCompiler()
```

### Lock/Unlock flow

```go
// Lock
lockReq := &LockAssetRequest{
    OwnerAddress: addr,
    OutputID:     outputID,
    LockDuration: 24 * time.Hour,
    LockScript:   "after(unlock_time)",
}
lockResp, err := svc.LockAsset(ctx, lockReq)

// Wait for unlock time...

// Unlock
unlockReq := &UnlockAssetRequest{
    AssetID: lockResp.AssetID,
}
unlockResp, err := svc.UnlockAsset(ctx, unlockReq)
```

### Emergency Unlock

```go
// Только для Standard+ тиров
err := svc.EmergencyUnlock(
    assetID,
    accessToken,          // HMAC token
    nonce,                // timestamp:random (single-use)
    [][]byte{sig1, sig2}, // multi-sig
    "emergency reason",
)
// Добавляет delay перед unlock
```

## Зависимости

- **От:** `crypto`, `lockscript`, `verification`, `interfaces`, `payment`, `logging`
- **Используется в:** `grpc_server`, main

## Тесты

```bash
go test ./internal/service/... -v
```

## Известные проблемы

### 1. CreateMultiSig не реализован
```
Возвращает codes.Unimplemented в gRPC server
```

### 2. Geo-distribution не реализована
```
Redundant copies хранятся локально с разными ключами.
В production нужна интеграция с RedundancyManager из storage пакета.
```
