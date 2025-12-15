# План исправления интеграционных проблем LockBox

## Обзор проблем

### 1. gRPC/Protobuf не сгенерирован
- `internal/proto/lockbox.pb.go` - пустой placeholder
- Нет `lockbox_grpc.pb.go` для gRPC сервисов

### 2. Дублирование типов
- `service.Tier` vs `interfaces.Tier`
- `service.LockedAsset` vs `interfaces.LockedAsset`
- `service.StorageManager` vs `verification.StorageManager` (интерфейс)

### 3. Import cycle
- service → monitoring → verification → service

### 4. Несовместимость API
- `iotago.ParseBech32` возвращает 3 значения, код ожидает 2

---

## Архитектурные решения (по примеру Hornet/INX)

### Принцип 1: Единый источник типов
Hornet использует `pkg/model/` как единый источник типов данных.

**Применение к LockBox:**
```
internal/
├── interfaces/          # Интерфейсы (НЕ типы данных)
│   ├── storage.go       # StorageProvider interface
│   ├── verifier.go      # Verifier interface
│   └── service.go       # AssetService interface
│
├── model/               # НОВЫЙ: Единый источник типов
│   ├── types.go         # Tier, AssetStatus, LockedAsset
│   ├── requests.go      # LockAssetRequest, UnlockAssetRequest
│   └── responses.go     # LockAssetResponse, UnlockAssetResponse
```

### Принцип 2: Protobuf в отдельной директории
Hornet/INX держит proto файлы в `proto/` и генерирует код.

**Применение к LockBox:**
```
proto/
├── lockbox.proto        # Определения
├── generate.sh          # Скрипт генерации

internal/proto/
├── lockbox.pb.go        # Сгенерированные сообщения
└── lockbox_grpc.pb.go   # Сгенерированный gRPC код
```

### Принцип 3: Dependency Injection
Hornet использует `go.uber.org/dig` для DI.

**Применение к LockBox:**
Можно использовать проще - через интерфейсы и конструкторы.

---

## План исправления по шагам

### Фаза 1: Унификация типов (приоритет: высокий)

#### Шаг 1.1: Создать `internal/model/`
```go
// internal/model/types.go
package model

type Tier int
const (
    TierBasic Tier = iota
    TierStandard
    TierPremium
    TierElite
)

type AssetStatus string
const (
    AssetStatusLocked    AssetStatus = "locked"
    AssetStatusUnlocking AssetStatus = "unlocking"
    AssetStatusUnlocked  AssetStatus = "unlocked"
)

type LockedAsset struct {
    ID              string
    OwnerAddress    iotago.Address
    // ... все поля
}
```

#### Шаг 1.2: Обновить `internal/interfaces/`
```go
// internal/interfaces/storage.go
package interfaces

import "github.com/dueldanov/lockbox/v2/internal/model"

type StorageManager interface {
    GetLockedAsset(assetID string) (*model.LockedAsset, error)
    StoreLockedAsset(asset *model.LockedAsset) error
    // ...
}
```

#### Шаг 1.3: Обновить все пакеты использовать `model.*`
- `internal/service/` → `model.Tier`, `model.LockedAsset`
- `internal/verification/` → `model.Tier`, `model.LockedAsset`
- `internal/monitoring/` → `model.*`

**Файлы для изменения:**
- [ ] Создать `internal/model/types.go`
- [ ] Создать `internal/model/requests.go`
- [ ] Создать `internal/model/responses.go`
- [ ] Обновить `internal/interfaces/service.go`
- [ ] Обновить `internal/service/service.go`
- [ ] Обновить `internal/service/storage.go`
- [ ] Обновить `internal/verification/verifier.go`
- [ ] Удалить `internal/service/types.go` (перенесено в model)

---

### Фаза 2: Генерация Protobuf (приоритет: средний)

#### Шаг 2.1: Обновить proto файл
```protobuf
// proto/lockbox.proto
syntax = "proto3";

package lockbox;

option go_package = "github.com/dueldanov/lockbox/v2/internal/proto";

service LockBoxService {
    rpc LockAsset(LockAssetRequest) returns (LockAssetResponse);
    // ...
}
```

#### Шаг 2.2: Создать скрипт генерации
```bash
#!/bin/bash
# proto/generate.sh

protoc \
    --go_out=../internal/proto \
    --go_opt=paths=source_relative \
    --go-grpc_out=../internal/proto \
    --go-grpc_opt=paths=source_relative \
    lockbox.proto
```

#### Шаг 2.3: Добавить зависимости
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

**Файлы для изменения:**
- [ ] Обновить `proto/lockbox.proto` (go_package)
- [ ] Создать `proto/generate.sh`
- [ ] Запустить генерацию
- [ ] Обновить `internal/service/grpc_server.go`

---

### Фаза 3: Исправление gRPC сервера (приоритет: средний)

#### Шаг 3.1: Обновить grpc_server.go
```go
// После генерации proto

func (s *GRPCServer) LockAsset(ctx context.Context, req *pb.LockAssetRequest) (*pb.LockAssetResponse, error) {
    // Конвертация pb.* → model.*
    modelReq := &model.LockAssetRequest{
        OwnerAddress: parseAddress(req.OwnerAddress),
        // ...
    }

    resp, err := s.service.LockAsset(ctx, modelReq)
    if err != nil {
        return nil, status.Error(codes.Internal, err.Error())
    }

    // Конвертация model.* → pb.*
    return &pb.LockAssetResponse{
        AssetId: resp.AssetID,
        // ...
    }, nil
}
```

#### Шаг 3.2: Исправить iotago.ParseBech32
```go
// Было (неправильно):
hrp, addr, err := iotago.ParseBech32(address)

// Стало (правильно):
hrp, addr, err := iotago.ParseBech32(address)
// или если 3 значения:
network, addr, err := iotago.ParseBech32(address)
```

**Файлы для изменения:**
- [ ] `internal/service/grpc_server.go.disabled` → включить и исправить
- [ ] Добавить конвертеры pb ↔ model

---

### Фаза 4: Восстановление service_additions (приоритет: низкий)

#### Шаг 4.1: После унификации типов
```go
// internal/service/service_additions.go

func (s *Service) InitializeVerification() error {
    s.nodeSelector = verification.NewNodeSelector(s.WrappedLogger.Logger())
    // ... теперь типы совместимы
}
```

#### Шаг 4.2: Добавить GetAllNodes в NodeSelector
```go
// internal/verification/selector.go

func (ns *NodeSelector) GetAllNodes() []*VerificationNode {
    ns.mu.RLock()
    defer ns.mu.RUnlock()

    nodes := make([]*VerificationNode, 0, len(ns.nodes))
    for _, node := range ns.nodes {
        nodes = append(nodes, node)
    }
    return nodes
}
```

**Файлы для изменения:**
- [ ] `internal/service/service_additions.go.disabled` → включить
- [ ] `internal/service/storage_additions.go.disabled` → включить
- [ ] `internal/verification/selector.go` - добавить GetAllNodes

---

### Фаза 5: Тестирование

#### Интеграционные тесты
- [ ] gRPC сервер запускается
- [ ] LockAsset через gRPC работает
- [ ] Verification интеграция работает

#### Unit тесты
- [ ] Все существующие тесты проходят
- [ ] Добавить тесты для конвертеров pb ↔ model

---

## Порядок выполнения

```
Фаза 1 (Типы)     ──────────────────────────────►
                         │
Фаза 2 (Proto)           ├─────────────────────►
                         │         │
Фаза 3 (gRPC)            │         ├──────────►
                         │         │
Фаза 4 (Additions)       └─────────┴──────────►
                                              │
Фаза 5 (Тесты)                                └►
```

Фазы 1-2 можно делать параллельно.
Фаза 3 зависит от Фазы 2.
Фаза 4 зависит от Фазы 1.

---

## Ссылки

- [IOTA Hornet](https://github.com/iotaledger/hornet) - архитектура
- [IOTA INX](https://github.com/iotaledger/inx) - protobuf/gRPC паттерны
- [go.uber.org/dig](https://github.com/uber-go/dig) - DI (опционально)

---

## Оценка трудозатрат

| Фаза | Сложность | Файлов |
|------|-----------|--------|
| Фаза 1 | Средняя | ~10 |
| Фаза 2 | Низкая | ~3 |
| Фаза 3 | Средняя | ~2 |
| Фаза 4 | Низкая | ~3 |
| Фаза 5 | Низкая | ~5 |

**Итого:** ~23 файла для изменения/создания
