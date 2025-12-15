# LockBox Requirements Audit Report

**Дата:** 2024-12-15
**Версия кодовой базы:** feat/phase-3
**Документ требований:** LockBox Requirements.docx

---

## 1. Краткое резюме

Текущая реализация покрывает базовую архитектуру, но имеет значительные расхождения с требованиями в области:
- HKDF key derivation (отсутствуют purpose-specific параметры)
- Tier capabilities (не определены decoy ratios, shard copies)
- ZKP (используется Groth16 вместо zk-STARKs)
- Character-level sharding (не полностью реализовано)

---

## 2. Детальный анализ соответствия

### 2.1 HKDF Key Derivation

| Требование | Текущий статус | Файл |
|------------|----------------|------|
| Real chars: `LockBox:real-char:N` | ❌ Не реализовано | `internal/crypto/hkdf.go` |
| Decoy chars: `LockBox:decoy-char:A` | ❌ Не реализовано | - |
| Metadata real: `LockBoxMeta:real-meta:N` | ❌ Не реализовано | - |
| Metadata decoy: `LockBoxMeta:decoy-meta:A` | ❌ Не реализовано | - |

**Текущая реализация:** Использует generic info string `lockbox-hkdf-v1`

**Рекомендация эксперта:** Использовать единый числовой индекс и различать real/decoy только через purpose string в HKDF. Это убирает потолок алфавитной индексации (при 512 decoys алфавита не хватит).

### 2.2 Tier Capabilities

| Tier | Shard Copies | Decoy Ratio | Metadata Decoys | Geo Redundancy |
|------|--------------|-------------|-----------------|----------------|
| **Basic** | 3 (❓) | 0.5x (❌) | None (❌) | 3 → **1** ❌ |
| **Standard** | 5 (❓) | 1x (❌) | None (❌) | 3+ → **2** ❌ |
| **Premium** | 7 (❓) | 1.5x (❌) | 1:1 (❌) | 3 → **3** ✅ |
| **Elite** | 10+ (❓) | 2x (❌) | 2:1 (❌) | 5 → **5** ✅ |

**Файл:** `internal/service/tier.go`

**Отсутствующие поля в TierCapabilities:**
- `ShardCopies int`
- `DecoyRatio float64`
- `MetadataDecoyRatio float64`

### 2.3 ZKP Implementation

| Требование | Текущий статус | Комментарий |
|------------|----------------|-------------|
| zk-STARKs | ⚠️ Используется Groth16 | zk-SNARKs, не quantum-resistant |
| gnark library | ✅ | Библиотека используется |
| Ownership proofs | ✅ | `OwnershipProofCircuit` |
| Unlock proofs | ✅ | `UnlockConditionCircuit` |

**Файл:** `internal/crypto/zkp.go`

**Рекомендация эксперта:** Для v1 использовать подписи кошелька + nonce вместо тяжёлых ZKP. Оставить ZKP как plug-in для будущих версий.

### 2.4 Verification System

| Требование | Текущий статус | Файл |
|------------|----------------|------|
| Triple verification (3 nodes) | ✅ | `internal/verification/verifier.go` |
| Dual coordination | ⚠️ Один координатор | `internal/verification/selector.go` |
| Elite shard-level dual verification | ❌ | Не реализовано |

### 2.5 Character-Level Sharding

| Требование | Текущий статус | Комментарий |
|------------|----------------|-------------|
| Individual character shards | ⚠️ | `CharacterShard` есть, но fixed size |
| HKDF per character | ❌ | Generic key derivation |
| Decoy characters | ❌ | Не реализовано |

**Файл:** `internal/crypto/encrypt.go`

### 2.6 Geographic Distribution

| Требование | Текущий статус | Файл |
|------------|----------------|------|
| Min 3 regions | ✅ | `internal/storage/shard.go` |
| 1000km separation | ✅ | `GeographicVerifier` |
| Multi-cloud (5+ nodes, 3+ providers) | ✅ | Структура готова |

### 2.7 Token System

| Требование | Текущий статус | Файл |
|------------|----------------|------|
| 64-byte token | ✅ | `internal/verification/token_manager.go` |
| Nonce/timestamp | ✅ | В `VerificationToken` |
| 5-min validation window | ⚠️ | Настраивается, но не 5 мин по умолчанию |
| Rate limiting 5/min | ❌ | Не реализовано |

---

## 3. Архитектурные рекомендации эксперта

### 3.1 Главная развилка: DAG vs Off-Ledger Shards

**Проблема:** В требованиях одновременно:
- Сеть — fork Hornet/DAG (SecureHornet)
- "Не более 10% шардов ключа на ноду"

В классическом DAG ноды хранят всё, тогда "10% на ноду" не имеет смысла.

**Решение для v1:**
```
SecureHornet/DAG использовать как:
├── Ledger
├── Реестр/коммитменты
├── Платежи
├── Provider-ID
└── События

Шард-данные хранить OFF-LEDGER:
├── KV/object store на конкретных нодах
└── В DAG писать:
    ├── BundleID
    ├── hash(commitment) на каждый шард
    ├── Подпись ноды (receipt)
    └── node_id / endpoint
```

### 3.2 ZKP: Прагматичный подход для v1

**Рекомендация:**
- Делать интерфейс `Proof`, но запускать v1 на **подписи кошелька + nonce**
- ZKP оставить как plug-in
- Инвариант "ownership + anti-replay" покрывается nonce/5-мин окном

### 3.3 Индексация Decoys: Исправление

**Проблема:** При 256 символах + Elite 2x decoys = 512 decoys. Алфавита (A-Z, 26 букв) не хватит.

**Решение:**
```go
// Вместо алфавитного индекса:
"LockBox:decoy-char:A"  // ❌ Ограничено 26 символами

// Использовать числовой:
"LockBox:decoy-char:0"  // ✅ Без ограничений
"LockBox:decoy-char:511"
```

### 3.4 Транзакционный взрыв: Chunk Packing

**Проблема:**
- 256 real + 512 decoy = 768 шардов
- Elite 10 копий = 7680 записей на одно сохранение

**Решение:**
```
1. Шифровать каждый char своим HKDF-ключом (как задумано)
2. Хранить пачку шифртекстов одним "chunk object" (32-64 chars)
3. В DAG писать коммитменты на chunk'и

Смысл сохраняется (уникальные ключи, decoys, невозможность различить)
TPS/latency становятся реальнее
```

### 3.5 Гео-верификация: v1 подход

**Решение для v1:**
- Реестр нод: регион/провайдер/координаты как атрибуты
- Подписаны оператором/CA (mTLS уже есть)
- Latency как сигнал, не единственный "доказатель"
- zk-гео-доказательства — на потом

### 3.6 User ID и Rate Limiting

**Решение:**
```go
// "user ID" = публичный ключ идентичности кошелька
// Детерминированно выводится из master key (Argon2id)
// Подписывает запросы (вместо ZKP в v1)

// Rate limiting: token bucket в памяти нод
// При рестарте — окей, security даёт подпись+nonce
```

---

## 4. Definition of Done для Project 1 (MVP)

MVP считается готовым, если:

| # | Критерий | Статус |
|---|----------|--------|
| 1 | `StoreKey` → кладёт encrypted shards + metadata по правилам (≥3 региона, shard limit) | ⚠️ Частично |
| 2 | `RetrieveKey` → координация/подписи нод, сборка ключа только локально | ⚠️ Частично |
| 3 | Token rotation работает (старый инвалидируется, новый выдаётся) | ✅ |
| 4 | Payout job 00:01 UTC и retry/ручная очередь | ❌ |
| 5 | Ошибки `INSUFFICIENT_REGIONS`, `TOKEN_INVALID`, `RATE_LIMITED` возвращаются корректно | ⚠️ Частично |

---

## 5. Приоритеты исправлений

### Критичные (блокируют MVP)
1. **HKDF purpose-specific keys** — добавить `DeriveKeyForCharacter(index, isDecoy)`
2. **TierCapabilities** — добавить `ShardCopies`, `DecoyRatio`
3. **Rate limiting** — реализовать token bucket

### Важные (влияют на security model)
4. **Numeric indexing для decoys** — убрать алфавитный лимит
5. **Dual coordination** — добавить secondary coordinating node
6. **Error codes** — реализовать все коды из спеки

### Можно отложить (v1+)
7. **zk-STARKs** — оставить Groth16, ZKP как plug-in
8. **Elite shard-level verification** — после базового MVP
9. **zk-гео-доказательства** — использовать реестр нод

---

## 6. Файлы требующие изменений

| Файл | Изменения |
|------|-----------|
| `internal/crypto/hkdf.go` | Добавить purpose-specific derivation |
| `internal/service/tier.go` | Добавить ShardCopies, DecoyRatio, MetadataDecoyRatio |
| `internal/service/types.go` | Добавить error codes |
| `internal/verification/verifier.go` | Dual coordination |
| `internal/verification/rate_limiter.go` | Создать новый файл |
| `internal/crypto/encrypt.go` | Chunk packing |

---

*Отчёт сгенерирован автоматически на основе анализа кодовой базы и требований*
