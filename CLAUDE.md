# CLAUDE.md - Инструкции для AI-ассистента

## Документация проекта

- **[Полная архитектура проекта](docs/ARCHITECTURE.md)** - логика, компоненты, потоки данных
- [План разработки Phase 1](docs/PHASE_1_DEV_DETAILED.md)
- [План интеграции](docs/INTEGRATION_FIX_PLAN.md)
- [Security Assessment](docs/SECURITY_ASSESSMENT_REPORT_EN.md)

---

## Правила написания кода

### Docstrings (ОБЯЗАТЕЛЬНО для семантики)

Каждая публичная функция и тип ДОЛЖНЫ иметь docstring:

```go
// LockAsset блокирует актив на указанный срок.
//
// Создаёт запись о заблокированном активе, генерирует ownership proof
// с использованием ZKP, шифрует данные и сохраняет в storage.
//
// Parameters:
//   - ctx: контекст выполнения
//   - req: параметры блокировки (адрес, outputID, длительность, скрипт)
//
// Returns:
//   - LockAssetResponse с assetID и временными метками
//   - error если валидация не прошла или storage недоступен
//
// Example:
//   resp, err := svc.LockAsset(ctx, &LockAssetRequest{
//       OwnerAddress: addr,
//       LockDuration: 24 * time.Hour,
//   })
func (s *Service) LockAsset(ctx context.Context, req *LockAssetRequest) (*LockAssetResponse, error)
```

### Типы - всегда с комментариями

```go
// LockedAsset представляет заблокированный актив в системе LockBox.
//
// Содержит всю информацию о блокировке: владелец, время,
// условия разблокировки и multi-sig настройки.
type LockedAsset struct {
    // ID уникальный идентификатор актива (16 байт hex)
    ID string

    // OwnerAddress IOTA адрес владельца актива
    OwnerAddress iotago.Address

    // UnlockTime время когда актив может быть разблокирован
    UnlockTime time.Time

    // Status текущий статус (locked, unlocking, unlocked, expired, emergency)
    Status AssetStatus

    // MultiSigAddresses адреса для multi-sig разблокировки (опционально)
    MultiSigAddresses []iotago.Address

    // MinSignatures минимум подписей для разблокировки
    MinSignatures int
}
```

### Константы - с описанием значений

```go
// AssetStatus определяет возможные статусы заблокированного актива.
type AssetStatus string

const (
    // AssetStatusLocked актив заблокирован и ожидает разблокировки
    AssetStatusLocked AssetStatus = "locked"

    // AssetStatusUnlocked актив успешно разблокирован
    AssetStatusUnlocked AssetStatus = "unlocked"

    // AssetStatusEmergency инициирована экстренная разблокировка
    AssetStatusEmergency AssetStatus = "emergency"
)
```

---

## Как решать задачи

### Алгоритм работы:

1. **Понять задачу**
   - Прочитать связанные файлы
   - Найти существующие паттерны

2. **Найти контекст**
   - Посмотреть в [ARCHITECTURE.md](docs/ARCHITECTURE.md) где эта задача
   - Определить какие компоненты затрагиваются

3. **Проверить зависимости**
   - Что импортирует файл
   - Кто использует этот код

4. **Написать код**
   - С docstrings и комментариями
   - Следуя существующим паттернам

5. **Протестировать**
   ```bash
   go build ./internal/...
   go test ./internal/... -v
   ```

6. **Проверить**
   - Нет ли новых ошибок компиляции
   - Проходят ли существующие тесты

### При исправлении багов:

1. Найти **root cause** (не симптом)
2. Проверить что исправление не ломает другое
3. Добавить тест если возможно
4. Документировать что было исправлено

### При добавлении фич:

1. Проверить **tier capabilities** - не все фичи доступны всем тирам
2. Следовать существующим паттернам кода
3. Обновить proto если нужен новый API endpoint
4. Добавить тесты

---

## Важные файлы проекта

### Ядро сервиса
| Файл | Описание |
|------|----------|
| `internal/service/service.go` | Главная бизнес-логика (Lock/Unlock) |
| `internal/service/types.go` | Типы данных (LockedAsset, Request/Response) |
| `internal/service/tier.go` | Возможности тиров (Basic → Elite) |
| `internal/service/grpc_server.go` | gRPC сервер |

### Криптография
| Файл | Описание |
|------|----------|
| `internal/crypto/hkdf.go` | Деривация ключей HKDF-SHA256 |
| `internal/crypto/encrypt.go` | Шифрование шардов ChaCha20Poly1305 |
| `internal/crypto/zkp.go` | Zero-knowledge proofs (Groth16) |
| `internal/crypto/keystore.go` | Хранение master key |

### LockScript
| Файл | Описание |
|------|----------|
| `internal/lockscript/engine.go` | Движок скриптов |
| `internal/lockscript/vm.go` | Виртуальная машина |
| `internal/lockscript/lexer.go` | Токенизация |
| `internal/lockscript/parser.go` | Построение AST |

### API
| Файл | Описание |
|------|----------|
| `internal/proto/lockbox.proto` | Определения gRPC сервиса |
| `internal/proto/generate.sh` | Скрипт генерации protobuf |

---

## Текущий статус

### Завершено:
- ✅ Phase 1: deserializeShard, getOwnershipProof, Ed25519 signing, renaming
- ✅ Phase 1.5: GetAssetStatus, ListAssets, EmergencyUnlock
- ✅ Phase 2: Protobuf generation + gRPC server

### В работе:
- Phase 3: Унификация типов, verification layer

### Известные проблемы:
- Ошибки компиляции в `tiering`, `core`, `security`, `storage`, `performance`
- `CreateMultiSig` не реализован (возвращает Unimplemented)
- Import cycles в некоторых пакетах

---

## Команды для разработки

```bash
# Сборка основных пакетов
go build ./internal/proto/... ./internal/service/... ./internal/crypto/...

# Запуск тестов
go test ./internal/service/... -v

# Генерация protobuf (после изменения .proto)
cd internal/proto && ./generate.sh

# Проверка форматирования
gofmt -s -w .
```

---

## Архитектурные принципы

1. **Модульность** - чёткое разделение по пакетам
2. **Интерфейсы** - абстракции для тестирования
3. **Безопасность** - defense in depth
4. **Тиры** - разные возможности по уровню
5. **IOTA** - интеграция с блокчейном
