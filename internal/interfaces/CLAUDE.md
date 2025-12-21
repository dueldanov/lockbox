# Модуль: interfaces

## Назначение

Общие типы для избежания import cycles между пакетами.

**Критически важно:** Этот пакет НЕ должен импортировать другие internal пакеты!

## Зачем нужен

```
Проблема:
service → verification (для Verifier)
verification → service (для Tier, LockedAsset)
= IMPORT CYCLE

Решение:
interfaces ← service (реэкспортирует типы)
interfaces ← verification (использует интерфейсы)
```

## Файлы

| Файл | Содержимое |
|------|------------|
| `service.go` | Tier, AssetStatus, LockedAsset, интерфейсы |

## Типы

```go
// Tier уровень сервиса
type Tier int

const (
    TierBasic Tier = iota
    TierStandard
    TierPremium
    TierElite
)

// AssetStatus статус актива
type AssetStatus string

const (
    AssetStatusLocked    AssetStatus = "locked"
    AssetStatusUnlocking AssetStatus = "unlocking"
    AssetStatusUnlocked  AssetStatus = "unlocked"
    AssetStatusExpired   AssetStatus = "expired"
    AssetStatusEmergency AssetStatus = "emergency"
)

// LockedAsset заблокированный актив
type LockedAsset struct {
    ID                string
    OwnerAddress      iotago.Address
    OutputID          iotago.OutputID
    LockTime          time.Time
    UnlockTime        time.Time
    LockScript        string
    MultiSigAddresses []iotago.Address
    MinSignatures     int
    Status            AssetStatus
}
```

## Интерфейсы

```go
// AssetService интерфейс для verification
type AssetService interface {
    GetAssetStatus(ctx context.Context, assetID string) (string, error)
    ValidateAssetOwnership(ctx context.Context, assetID string, address iotago.Address) (bool, error)
    GetAssetLockTime(ctx context.Context, assetID string) (int64, error)
}

// StorageProvider интерфейс для storage
type StorageProvider interface {
    Get(key []byte) ([]byte, error)
    Set(key, value []byte) error
    Delete(key []byte) error
    Has(key []byte) (bool, error)
}
```

## Паттерны использования

### В service/types.go - реэкспорт

```go
package service

import "github.com/dueldanov/lockbox/v2/internal/interfaces"

// Type aliases
type Tier = interfaces.Tier

const (
    TierBasic    = interfaces.TierBasic
    TierStandard = interfaces.TierStandard
    TierPremium  = interfaces.TierPremium
    TierElite    = interfaces.TierElite
)

type LockedAsset = interfaces.LockedAsset
type AssetStatus = interfaces.AssetStatus
```

### В verification - использовать интерфейсы

```go
package verification

import "github.com/dueldanov/lockbox/v2/internal/interfaces"

type Verifier struct {
    assetService interfaces.AssetService // ← интерфейс!
}
```

### В тестах

```go
// ❌ НЕПРАВИЛЬНО
import "github.com/dueldanov/lockbox/v2/internal/service"
tier := service.TierStandard

// ✅ ПРАВИЛЬНО
import "github.com/dueldanov/lockbox/v2/internal/interfaces"
tier := interfaces.TierStandard
```

## Зависимости

- **От:** НИЧЕГО (только stdlib + iotago)
- **Используется в:** `service`, `verification`, `crypto`

## Правила

1. **Никаких internal импортов**
2. **Только типы и интерфейсы**
3. **Нет бизнес-логики**
4. **Минимальные зависимости**
