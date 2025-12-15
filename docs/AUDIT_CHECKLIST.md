# LockBox Implementation Audit Checklist

**Цель:** Этот документ предназначен для LLM-ассистента для проверки соответствия реализации требованиям.

**Инструкция:** Проверь каждый пункт, прочитав указанные файлы. Отметь статус: ✅ OK / ❌ FAIL / ⚠️ PARTIAL

---

## ЧАСТЬ 1: Криптография (internal/crypto/)

### 1.1 HKDF Key Derivation

**Файл:** `internal/crypto/hkdf.go`

- [ ] **CHECK-HKDF-001:** Функция `DeriveKeyForCharacter(index uint32, isDecoy bool)` существует
- [ ] **CHECK-HKDF-002:** Для real chars используется info string формата `LockBox:real-char:{index}`
- [ ] **CHECK-HKDF-003:** Для decoy chars используется info string формата `LockBox:decoy-char:{index}`
- [ ] **CHECK-HKDF-004:** Индексация decoys числовая (не алфавитная A,B,C)
- [ ] **CHECK-HKDF-005:** Salt генерируется случайно (32 байта) для каждого bundle
- [ ] **CHECK-HKDF-006:** Master key очищается из памяти после использования (`ClearBytes`)

**Команда проверки:**
```bash
grep -n "real-char\|decoy-char\|DeriveKeyForCharacter" internal/crypto/hkdf.go
```

### 1.2 Character-Level Encryption

**Файл:** `internal/crypto/encrypt.go`

- [ ] **CHECK-ENC-001:** Структура `CharacterShard` существует с полями: ID, Index, Total, Data, Nonce, Checksum
- [ ] **CHECK-ENC-002:** Каждый символ шифруется своим уникальным ключом (не batch encryption)
- [ ] **CHECK-ENC-003:** Используется ChaCha20-Poly1305 или AES-256-GCM
- [ ] **CHECK-ENC-004:** Nonce уникален для каждого шарда (24 байта для XChaCha20)
- [ ] **CHECK-ENC-005:** Контрольная сумма вычисляется для каждого шарда

**Команда проверки:**
```bash
grep -n "CharacterShard\|chacha20\|aes" internal/crypto/encrypt.go
```

### 1.3 ZKP (Zero-Knowledge Proofs)

**Файл:** `internal/crypto/zkp.go`

- [ ] **CHECK-ZKP-001:** Используется gnark библиотека
- [ ] **CHECK-ZKP-002:** `OwnershipProofCircuit` определён с public inputs: AssetCommitment, OwnerAddress
- [ ] **CHECK-ZKP-003:** `UnlockConditionCircuit` определён с public inputs: UnlockCommitment, CurrentTime, UnlockTime
- [ ] **CHECK-ZKP-004:** Методы `GenerateOwnershipProof` и `VerifyOwnershipProof` существуют
- [ ] **CHECK-ZKP-005:** Nonce включён в proof для защиты от replay attacks

**Команда проверки:**
```bash
grep -n "OwnershipProofCircuit\|UnlockConditionCircuit\|gnark" internal/crypto/zkp.go
```

### 1.4 Memory Security

**Файл:** `internal/crypto/memory.go`

- [ ] **CHECK-MEM-001:** Функция `ClearBytes([]byte)` существует и зануляет slice
- [ ] **CHECK-MEM-002:** `TimedClear` структура для автоматической очистки через время
- [ ] **CHECK-MEM-003:** Все криптографические ключи очищаются после использования

**Команда проверки:**
```bash
grep -n "ClearBytes\|TimedClear\|defer.*Clear" internal/crypto/*.go
```

---

## ЧАСТЬ 2: Сервис и Тиры (internal/service/)

### 2.1 Tier Capabilities

**Файл:** `internal/service/tier.go`

- [ ] **CHECK-TIER-001:** Определены 4 тира: Basic, Standard, Premium, Elite
- [ ] **CHECK-TIER-002:** `TierCapabilities` содержит поле `ShardCopies` (Basic:3, Standard:5, Premium:7, Elite:10+)
- [ ] **CHECK-TIER-003:** `TierCapabilities` содержит поле `DecoyRatio` (Basic:0.5, Standard:1.0, Premium:1.5, Elite:2.0)
- [ ] **CHECK-TIER-004:** `TierCapabilities` содержит поле `MetadataDecoyRatio` (Basic:0, Standard:0, Premium:1.0, Elite:2.0)
- [ ] **CHECK-TIER-005:** `GeographicRedundancy` минимум 3 для всех тиров
- [ ] **CHECK-TIER-006:** Методы `String()` и `TierFromString()` существуют

**Команда проверки:**
```bash
grep -n "ShardCopies\|DecoyRatio\|GeographicRedundancy" internal/service/tier.go
```

### 2.2 Service Methods

**Файл:** `internal/service/service.go`

- [ ] **CHECK-SVC-001:** Метод `LockAsset(ctx, *LockAssetRequest) (*LockAssetResponse, error)` существует
- [ ] **CHECK-SVC-002:** Метод `UnlockAsset(ctx, *UnlockAssetRequest) (*UnlockAssetResponse, error)` существует
- [ ] **CHECK-SVC-003:** Метод `GetAssetStatus(assetID string) (*LockedAsset, error)` существует
- [ ] **CHECK-SVC-004:** Метод `ListAssets(owner, statusFilter) ([]*LockedAsset, error)` существует
- [ ] **CHECK-SVC-005:** Метод `EmergencyUnlock(assetID, signatures, reason) error` существует
- [ ] **CHECK-SVC-006:** Метод `CreateMultiSig(ctx, addresses, minSignatures) (*MultiSigConfig, error)` существует

**Команда проверки:**
```bash
grep -n "func (s \*Service)" internal/service/service.go | head -20
```

### 2.3 Error Codes

**Файл:** `internal/service/service.go` или `internal/errors/`

- [ ] **CHECK-ERR-001:** `ErrAssetNotFound` определена
- [ ] **CHECK-ERR-002:** `ErrUnauthorized` определена
- [ ] **CHECK-ERR-003:** `ErrInvalidUnlockTime` определена
- [ ] **CHECK-ERR-004:** `INSUFFICIENT_REGIONS` error определена
- [ ] **CHECK-ERR-005:** `TOKEN_INVALID` error определена
- [ ] **CHECK-ERR-006:** `RATE_LIMITED` error определена

**Команда проверки:**
```bash
grep -rn "Err.*=.*errors.New\|INSUFFICIENT\|TOKEN_INVALID\|RATE_LIMITED" internal/
```

---

## ЧАСТЬ 3: Verification System (internal/verification/)

### 3.1 Node Selector

**Файл:** `internal/verification/selector.go`

- [ ] **CHECK-SEL-001:** `NodeSelector` структура существует
- [ ] **CHECK-SEL-002:** `SelectNodes(ctx, tier, preferredRegions) ([]*VerificationNode, error)` метод существует
- [ ] **CHECK-SEL-003:** Для Basic/Standard/Premium выбираются 3 ноды (triple verification)
- [ ] **CHECK-SEL-004:** Для Elite выбираются 2 ноды (dual verification)
- [ ] **CHECK-SEL-005:** Ноды выбираются из разных регионов (geographic diversity)

**Команда проверки:**
```bash
grep -n "SelectNodes\|count.*3\|count.*2" internal/verification/selector.go
```

### 3.2 Verifier

**Файл:** `internal/verification/verifier.go`

- [ ] **CHECK-VER-001:** `Verifier` структура существует
- [ ] **CHECK-VER-002:** `VerifyAsset(ctx, *VerificationRequest) (*VerificationResult, error)` метод существует
- [ ] **CHECK-VER-003:** Consensus threshold = nodes/2 + 1 (большинство)
- [ ] **CHECK-VER-004:** Результаты кэшируются (`VerificationCache`)
- [ ] **CHECK-VER-005:** Timeout для verification (по умолчанию 10 секунд)

**Команда проверки:**
```bash
grep -n "consensusThreshold\|VerificationCache\|verificationTimeout" internal/verification/verifier.go
```

### 3.3 Token Manager

**Файл:** `internal/verification/token_manager.go`

- [ ] **CHECK-TOK-001:** `TokenManager` структура существует
- [ ] **CHECK-TOK-002:** `VerificationToken` содержит: ID, Secret, CreatedAt, ExpiresAt
- [ ] **CHECK-TOK-003:** Token rotation реализована
- [ ] **CHECK-TOK-004:** Expired tokens отклоняются
- [ ] **CHECK-TOK-005:** Token validity period настраивается

**Команда проверки:**
```bash
grep -n "VerificationToken\|ExpiresAt\|Rotate" internal/verification/token_manager.go
```

### 3.4 Rate Limiter

**Файл:** `internal/verification/rate_limiter.go` (может не существовать)

- [ ] **CHECK-RATE-001:** Rate limiter существует
- [ ] **CHECK-RATE-002:** Лимит 5 запросов в минуту на user ID
- [ ] **CHECK-RATE-003:** Token bucket алгоритм или sliding window

**Команда проверки:**
```bash
ls -la internal/verification/rate_limiter.go 2>/dev/null || echo "FILE NOT FOUND"
```

---

## ЧАСТЬ 4: Storage и Geographic Distribution (internal/storage/)

### 4.1 Shard Distribution

**Файл:** `internal/storage/shard.go`

- [ ] **CHECK-SHARD-001:** `Shard` структура с полями: ID, Index, TotalShards, Data, Hash
- [ ] **CHECK-SHARD-002:** `ShardDistribution` структура с полями: ShardID, Locations, Redundancy
- [ ] **CHECK-SHARD-003:** `ShardDistributionAlgorithm` реализует распределение по тирам
- [ ] **CHECK-SHARD-004:** Лимит "не более 10% шардов ключа на ноду" реализован
- [ ] **CHECK-SHARD-005:** Self-healing: обнаружение и перераспределение при failure

**Команда проверки:**
```bash
grep -n "ShardDistribution\|Redundancy\|10.*percent\|self.*heal" internal/storage/shard.go
```

### 4.2 Geographic Verifier

**Файл:** `internal/storage/shard.go`

- [ ] **CHECK-GEO-001:** `GeographicVerifier` структура существует
- [ ] **CHECK-GEO-002:** Минимум 3 региона проверяется
- [ ] **CHECK-GEO-003:** Регионы определены (us-east, us-west, eu-west, asia-pacific)
- [ ] **CHECK-GEO-004:** `VerifyDiversity(locations) error` метод существует
- [ ] **CHECK-GEO-005:** Latency между регионами определена

**Команда проверки:**
```bash
grep -n "GeographicVerifier\|VerifyDiversity\|1000.*km\|regions" internal/storage/shard.go
```

---

## ЧАСТЬ 5: gRPC API (internal/proto/, internal/service/grpc_server.go)

### 5.1 Proto Definitions

**Файл:** `internal/proto/lockbox.proto`

- [ ] **CHECK-PROTO-001:** `LockAssetRequest` message определён
- [ ] **CHECK-PROTO-002:** `UnlockAssetRequest` message определён
- [ ] **CHECK-PROTO-003:** `GetAssetStatusRequest` message определён
- [ ] **CHECK-PROTO-004:** `CreateMultiSigRequest` message определён
- [ ] **CHECK-PROTO-005:** `EmergencyUnlockRequest` message определён

**Команда проверки:**
```bash
grep -n "message.*Request" internal/proto/lockbox.proto
```

### 5.2 gRPC Server

**Файл:** `internal/service/grpc_server.go`

- [ ] **CHECK-GRPC-001:** `GRPCServer` структура реализует `pb.LockBoxServiceServer`
- [ ] **CHECK-GRPC-002:** TLS поддержка (tlsEnabled, tlsCertPath, tlsKeyPath)
- [ ] **CHECK-GRPC-003:** Keepalive настроен
- [ ] **CHECK-GRPC-004:** Все методы из proto реализованы

**Команда проверки:**
```bash
grep -n "func (s \*GRPCServer)" internal/service/grpc_server.go
```

---

## ЧАСТЬ 6: Interfaces и типы (internal/interfaces/)

### 6.1 Type Definitions

**Файл:** `internal/interfaces/service.go`

- [ ] **CHECK-INT-001:** `Tier` тип определён с константами Basic, Standard, Premium, Elite
- [ ] **CHECK-INT-002:** `AssetStatus` тип определён (locked, unlocking, unlocked, expired, emergency)
- [ ] **CHECK-INT-003:** `LockedAsset` структура с JSON тегами
- [ ] **CHECK-INT-004:** `AssetService` интерфейс определён
- [ ] **CHECK-INT-005:** `StorageProvider` интерфейс определён
- [ ] **CHECK-INT-006:** `ErrAssetNotFound` error определена

**Команда проверки:**
```bash
grep -n "type.*interface\|type Tier\|type AssetStatus\|type LockedAsset" internal/interfaces/service.go
```

---

## ЧАСТЬ 7: Build и Tests

### 7.1 Compilation

- [ ] **CHECK-BUILD-001:** `go build ./...` успешно без ошибок
- [ ] **CHECK-BUILD-002:** Нет unused imports
- [ ] **CHECK-BUILD-003:** Нет циклических зависимостей

**Команда проверки:**
```bash
go build ./... 2>&1
```

### 7.2 Tests

- [ ] **CHECK-TEST-001:** `go test ./internal/crypto/...` проходит
- [ ] **CHECK-TEST-002:** `go test ./internal/service/...` проходит
- [ ] **CHECK-TEST-003:** `go test ./internal/verification/...` проходит
- [ ] **CHECK-TEST-004:** Test coverage > 50% для критичных пакетов

**Команда проверки:**
```bash
go test ./... -v 2>&1 | tail -50
```

---

## ИТОГОВЫЙ ОТЧЁТ

После проверки заполни таблицу:

| Часть | Пройдено | Провалено | Частично |
|-------|----------|-----------|----------|
| 1. Криптография | | | |
| 2. Сервис/Тиры | | | |
| 3. Verification | | | |
| 4. Storage/Geo | | | |
| 5. gRPC API | | | |
| 6. Interfaces | | | |
| 7. Build/Tests | | | |

**Критичные проблемы (блокируют релиз):**
1. ...
2. ...

**Важные проблемы (нужно исправить):**
1. ...
2. ...

**Рекомендации:**
1. ...
2. ...

---

*Checklist version: 1.0*
*Last updated: 2024-12-15*
