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
| `compiler.go` | LockScript integration (TODO) |

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

    // Verification
    verifier        *verification.Verifier
    nodeSelector    *verification.NodeSelector

    // State
    lockedAssets    map[string]*LockedAsset
    pendingUnlocks  map[string]time.Time
    scriptCompiler  interface{} // TODO: *lockscript.Engine
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
}
```

## API методы

### LockAsset

```go
func (s *Service) LockAsset(ctx context.Context, req *LockAssetRequest) (*LockAssetResponse, error)
```

**Что делает сейчас:**
1. Валидация duration
2. Генерация assetID
3. Создание ownership proof (ZKP)
4. Шифрование данных
5. Сохранение шардов
6. Сохранение asset в storage

**Что НЕ делает (TODO):**
- ❌ Вызов DecoyGenerator
- ❌ Применение tier.ShardCopies
- ❌ Компиляция LockScript
- ❌ Geo-distribution

### UnlockAsset

```go
func (s *Service) UnlockAsset(ctx context.Context, req *UnlockAssetRequest) (*UnlockAssetResponse, error)
```

**Что делает:**
1. Получение asset
2. Проверка unlock time
3. Верификация ownership proof
4. Расшифровка шардов

**Что НЕ делает (TODO):**
- ❌ Исполнение LockScript
- ❌ Проверка multi-sig (TODO на line 587)
- ❌ Извлечение real shards из mixed

## Tier Capabilities

```go
caps := GetCapabilities(TierStandard)

// Basic:    ShardCopies=3,  DecoyRatio=0.5, MultiSig=false
// Standard: ShardCopies=5,  DecoyRatio=1.0, MultiSig=true
// Premium:  ShardCopies=7,  DecoyRatio=1.5, MultiSig=true
// Elite:    ShardCopies=10, DecoyRatio=2.0, MultiSig=true
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
    [][]byte{sig1, sig2}, // multi-sig
    "emergency reason",
)
// Добавляет delay перед unlock
```

## Зависимости

- **От:** `crypto`, `lockscript`, `verification`, `interfaces`
- **Используется в:** `grpc_server`, main

## Тесты

```bash
go test ./internal/service/... -v

# ПРОБЛЕМА: падает из-за logger
# Решение: добавить initTestLogger()
```

## Важные проблемы

### 1. TestLockAsset падает

```go
// service_test.go:16
func TestLockAsset(t *testing.T) {
    svc := setupTestService(t)  // ← panic: logger not initialized
}

// Решение: добавить в setupTestService()
initLoggerOnce.Do(func() {
    cfg := configuration.New()
    logger.InitGlobalLogger(cfg)
})
```

### 2. InitializeCompiler = заглушка

```go
// service.go:328
func (s *Service) InitializeCompiler() error {
    // This will be implemented with the LockScript compiler
    return nil  // ← TODO
}

// Нужно:
func (s *Service) InitializeCompiler() error {
    engine := lockscript.NewEngine(nil, 65536, 5*time.Second)
    engine.RegisterBuiltinFunctions()
    s.scriptCompiler = engine
    return nil
}
```

### 3. Decoys не интегрированы

```go
// service.go:163 - после шифрования, ДО сохранения
shards, err := s.shardEncryptor.EncryptData(assetData)

// TODO: добавить
caps := GetCapabilities(s.config.Tier)
gen := crypto.NewDecoyGenerator()
decoys := gen.GenerateDecoyShards(shards, caps.DecoyRatio)
mixer := crypto.NewShardMixer()
mixed, indexMap := mixer.Mix(shards, decoys)
// сохранять indexMap вместе с asset
```

### 4. Multi-sig не проверяется

```go
// service.go:587
// TODO: Verify each signature against MultiSigAddresses

// Нужно:
for i, sig := range signatures {
    addr := asset.MultiSigAddresses[i]
    if !lockscript.VerifyEd25519Signature(addr.String(), assetID, hex.EncodeToString(sig)) {
        return fmt.Errorf("invalid signature")
    }
}
```
