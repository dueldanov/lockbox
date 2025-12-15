# LockBox - Полная архитектура и логика проекта

## Обзор

**LockBox** - система управления заблокированными активами на базе IOTA HORNET v2.0.2.
Позволяет блокировать цифровые активы на время с условиями разблокировки.

### Что делает LockBox:
- Блокирует активы на указанный срок
- Обеспечивает условную разблокировку через LockScript
- Поддерживает multi-sig для критичных операций
- Предоставляет emergency unlock с задержкой
- Шифрует данные с помощью ZKP и ChaCha20

---

## Архитектура компонентов

```
┌─────────────────────────────────────────────────────────────┐
│                    LockBox Application                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              gRPC API (internal/proto/)                │ │
│  │  LockAsset | UnlockAsset | GetAssetStatus | ListAssets │ │
│  │  CreateMultiSig | EmergencyUnlock | GetServiceInfo     │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         Service Layer (internal/service/)              │ │
│  │  service.go - основная бизнес-логика                  │ │
│  │  types.go - типы данных (LockedAsset, Tier, etc)      │ │
│  │  tier.go - возможности тиров                          │ │
│  │  storage.go - работа с хранилищем                     │ │
│  │  grpc_server.go - gRPC сервер                         │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         Crypto Layer (internal/crypto/)                │ │
│  │  hkdf.go - деривация ключей HKDF-SHA256              │ │
│  │  encrypt.go - шифрование ChaCha20Poly1305            │ │
│  │  zkp.go - zero-knowledge proofs (Groth16)            │ │
│  │  keystore.go - хранение master key                   │ │
│  │  memory.go - безопасная очистка памяти               │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │      LockScript Engine (internal/lockscript/)          │ │
│  │  lexer.go - токенизация                               │ │
│  │  parser.go - построение AST                           │ │
│  │  vm.go - виртуальная машина                          │ │
│  │  opcodes.go - 30+ опкодов                            │ │
│  │  builtins.go - встроенные функции                    │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │     Verification Layer (internal/verification/)        │ │
│  │  verifier.go - консенсус 2/3 нод                     │ │
│  │  selector.go - выбор нод                             │ │
│  │  token_manager.go - rate limiting                    │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
└──────────────────────────────┼───────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   IOTA Protocol     │
                    │   (Pebble DB)       │
                    └─────────────────────┘
```

---

## Поток данных

### Блокировка актива (LockAsset)

```
1. Клиент → gRPC: LockAssetRequest
   {ownerAddress, outputID, lockDuration, lockScript, multiSigAddresses}

2. Service.LockAsset():
   a) Валидация запроса
   b) Генерация assetID (16 байт random hex)
   c) Расчёт lockTime, unlockTime

3. ZKPManager.GenerateOwnershipProof():
   a) Генерация ownerSecret (32 байта)
   b) Создание Groth16 proof
   c) Сохранение proof в storage

4. ShardEncryptor.EncryptData():
   a) Разбиение данных на шарды (4KB)
   b) Для каждого шарда:
      - Деривация ключа: HKDF(masterKey, shardID+index)
      - Шифрование: ChaCha20Poly1305
      - Расчёт checksum

5. Storage: сохранение шардов и метаданных

6. Ответ клиенту: {assetID, lockTime, unlockTime, status: "locked"}
```

### Разблокировка актива (UnlockAsset)

```
1. Клиент → gRPC: UnlockAssetRequest
   {assetID, signatures, unlockParams}

2. Service.UnlockAsset():
   a) Получение актива из storage
   b) Проверка времени: now >= unlockTime?
   c) Верификация ownership proof (ZKP)
   d) Верификация multi-sig (если настроено)
   e) Выполнение LockScript (если есть)

3. Расшифровка шардов:
   a) Получение шардов из storage
   b) Деривация ключей
   c) Расшифровка ChaCha20Poly1305
   d) Сборка полных данных

4. Обновление статуса: "unlocked"

5. Очистка шардов из storage

6. Ответ клиенту: {assetID, outputID, status: "unlocked"}
```

---

## Ключевые концепции

### 1. Тиры (Service Tiers)

| Возможность | Basic | Standard | Premium | Elite |
|-------------|-------|----------|---------|-------|
| Макс. блокировка | 30 дней | 1 год | 5 лет | 100 лет |
| Активов на пользователя | 10 | 100 | 1000 | ∞ |
| Multi-sig | ❌ | ✅ | ✅ | ✅ |
| Emergency unlock | ❌ | ✅ | ✅ | ✅ |
| Гео-redundancy | 1 | 2 | 3 | 5 |
| API лимит | 100/час | 1000/час | 10000/час | ∞ |

**Код:** `internal/service/tier.go`

### 2. Multi-sig

Требует M-of-N подписей для разблокировки:

```go
type LockedAsset struct {
    MultiSigAddresses []iotago.Address  // N адресов
    MinSignatures     int               // M минимум
}

// При разблокировке:
if len(signatures) < asset.MinSignatures {
    return ErrInsufficientSignatures
}
```

### 3. Emergency Unlock

Экстренная разблокировка с обязательной задержкой:

```go
func (s *Service) EmergencyUnlock(assetID string, signatures [][]byte, reason string) error {
    // 1. Проверка что фича включена для тира
    if !s.config.EnableEmergencyUnlock {
        return ErrNotEnabled
    }

    // 2. Верификация multi-sig
    if len(signatures) < asset.MinSignatures {
        return ErrInsufficientSignatures
    }

    // 3. Применение задержки (например, 7 дней)
    asset.UnlockTime = time.Now().Add(delayDuration)
    asset.Status = AssetStatusEmergency
}
```

### 4. Zero-Knowledge Proofs (ZKP)

Используется **Groth16** на кривой **BN254**:

```
OwnershipProofCircuit:
  Public: AssetCommitment, OwnerAddress
  Private: AssetID, OwnerSecret, Nonce

  Доказывает: "Я знаю secret который хеширует в commitment"
  Не раскрывая: сам secret
```

**Код:** `internal/crypto/zkp.go`

### 5. LockScript

Кастомный скриптовый язык для условной разблокировки:

```lockscript
// Пример: разблокировка после даты с проверкой подписи
if (timeCheck(1700000000)) {
    require(verifySignature(pubKey, message, sig), "Bad signature");
    transfer(beneficiary, 1000);
}
```

**Компоненты:**
- Lexer → Tokens
- Parser → AST
- Compiler → Bytecode
- VM → Execution

**Встроенные функции:**
- `timeCheck(timestamp)` - проверка времени
- `verifySignature(pubKey, msg, sig)` - Ed25519 верификация
- `hashCheck(data, hash)` - SHA256 проверка
- `geoCheck(location, regions)` - гео-ограничения

---

## Криптография

### HKDF (Key Derivation)

```
Master Key (32 байта, персистентный)
    │
    ▼ HKDF-SHA256 + salt
    │
Per-Shard Key = HKDF(masterKey, shardID || index)
```

### Shard Encryption

```
Алгоритм: ChaCha20Poly1305 (AEAD)
Размер ключа: 32 байта
Nonce: 24 байта (random)
Tag: 16 байт (Poly1305 MAC)
Размер шарда: 4KB (настраивается)
```

### Формат сериализации шарда

```
ID|Index|Total|Timestamp|DataHex|NonceHex|ChecksumHex

Пример:
12345|0|3|1702617600|6a7f8b9c...|a1b2c3d4...|f0e1d2c3...
```

---

## gRPC API

### Определения (internal/proto/lockbox.proto)

```protobuf
service LockBoxService {
  rpc LockAsset(LockAssetRequest) returns (LockAssetResponse);
  rpc UnlockAsset(UnlockAssetRequest) returns (UnlockAssetResponse);
  rpc GetAssetStatus(GetAssetStatusRequest) returns (GetAssetStatusResponse);
  rpc ListAssets(ListAssetsRequest) returns (stream ListAssetsResponse);
  rpc CreateMultiSig(CreateMultiSigRequest) returns (CreateMultiSigResponse);
  rpc EmergencyUnlock(EmergencyUnlockRequest) returns (EmergencyUnlockResponse);
  rpc GetServiceInfo(GetServiceInfoRequest) returns (GetServiceInfoResponse);
}
```

### LockAssetRequest

```protobuf
{
  owner_address: string,          // IOTA адрес
  output_id: bytes,               // IOTA output
  lock_duration_seconds: int64,   // Длительность
  lock_script: string,            // LockScript код
  multi_sig_addresses: [string],  // Адреса для multi-sig
  min_signatures: int32           // M из N
}
```

---

## Хранение данных

### Иерархия ключей в storage

```
asset_{assetID}           → LockedAsset JSON
proof_{assetID}           → CommitmentHex|OwnerAddrHex|Timestamp
shard_{assetID}_{index}   → ID|Index|Total|Timestamp|DataHex|NonceHex|ChecksumHex
```

### Backend: Pebble DB (IOTA UTXO Store)

---

## IOTA интеграция

LockBox построен как форк **IOTA HORNET v2.0.2**:

### Унаследовано от HORNET:
- Консенсус IOTA (Tangle)
- REST API (/api/core/v2/*)
- P2P gossip сеть
- UTXO ledger модель
- Milestone-based finality

### Добавлено LockBox:
- Asset locking service
- Zero-knowledge proof circuits
- LockScript VM
- Multi-sig management
- gRPC API

### Типы IOTA используемые в LockBox:
```go
iotago.Address        // Адреса
iotago.OutputID       // Идентификаторы outputs
iotago.NativeTokenID  // Native токены
iotago.MilestoneIndex // Индексы milestones
```

---

## Статусы активов

```go
const (
    AssetStatusLocked    = "locked"     // Заблокирован
    AssetStatusUnlocking = "unlocking"  // В процессе разблокировки
    AssetStatusUnlocked  = "unlocked"   // Разблокирован
    AssetStatusExpired   = "expired"    // Время вышло
    AssetStatusEmergency = "emergency"  // Emergency unlock инициирован
)
```

---

## Verification Layer

Распределённая верификация с консенсусом:

```
1. Запрос верификации
2. Проверка кеша (TTL: 5 мин)
3. Выбор нод (по тиру)
4. Параллельный запрос ко всем нодам
5. Ожидание консенсуса (2/3 нод)
6. Кеширование результата
7. Возврат результата
```

**Код:** `internal/verification/verifier.go`

---

## Директории проекта

```
lockbox/
├── internal/
│   ├── service/        # Бизнес-логика
│   ├── crypto/         # Криптография
│   ├── lockscript/     # Скриптовый движок
│   ├── verification/   # Верификация
│   ├── proto/          # gRPC definitions
│   ├── interfaces/     # Абстракции типов
│   ├── tiering/        # Управление тирами
│   └── storage/        # Хранилище
├── components/         # HORNET компоненты
├── docs/               # Документация
├── CLAUDE.md           # Инструкции для AI
└── main.go             # Точка входа
```

---

## Текущий статус разработки

### Завершено:
- ✅ Phase 1: deserializeShard, getOwnershipProof, Ed25519 signing
- ✅ Phase 1.5: GetAssetStatus, ListAssets, EmergencyUnlock
- ✅ Phase 2: Protobuf generation, gRPC server

### В работе:
- Phase 3: Унификация типов, verification layer, CreateMultiSig

### Известные проблемы:
- Ошибки компиляции в `tiering`, `core`, `security`, `storage`, `performance`
- Import cycles в некоторых пакетах

---

## Безопасность

### Криптографические примитивы:
- ChaCha20Poly1305 - AEAD шифрование
- SHA256 - хеши и checksums
- HKDF-SHA256 - деривация ключей
- Ed25519 - подписи
- Groth16 ZKP - zero-knowledge proofs

### Операционная безопасность:
- Master key с правами 0600
- Очистка памяти после использования
- Multi-sig для критичных операций
- Задержка для emergency unlock
