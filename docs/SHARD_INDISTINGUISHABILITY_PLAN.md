# Shard Indistinguishability — Полная реализация (v2)

**Дата:** 2025-12-25
**Версия:** 2.0 (исправлено по критике)
**Цель:** 100% приватность шардов — storage nodes не могут отличить real от decoy

---

## Исправления в этой версии

| Проблема | Исправление |
|----------|-------------|
| Trial decryption: ключ не менялся во внутреннем цикле | Ключ деривируется от `realIdx`, не `pos` |
| V2 формат: нет конкретики | Добавлен бинарный формат с кодом |
| Test helpers: не существуют | Добавлен `test_helpers.go` |
| Prerequisites: якобы не в коде | Проверено — они ЕСТЬ в service.go |

---

## Архитектурные изменения

### 1. Unified Key Derivation

**Было (уязвимо):**
```go
DeriveKeyForRealChar(idx)   → "LockBox:real-char:{idx}"
DeriveKeyForDecoyChar(idx)  → "LockBox:decoy-char:{letter}"
```

**Станет (безопасно):**
```go
DeriveKeyForPosition(bundleID, position) → "LockBox:shard:{bundleID}:{position}"
```

- Все шарды используют **одинаковый** контекст
- Различие: real шифруются с `position = originalIndex`, decoy с `position = randomPosition`
- При trial decryption: пробуем все позиции, успешная расшифровка = real

### 2. Storage Format v2

**Было (утечка):**
```
id|index|total|data|nonce|timestamp|checksum|shardType|originalIndex
                                             ↑ УТЕЧКА  ↑ УТЕЧКА
```

**Станет (uniform binary format):**
```
[1 byte: version=0x02]
[4 bytes: position (big-endian uint32)]
[24 bytes: nonce (XChaCha20-Poly1305)]
[N bytes: ciphertext (включает 16-byte auth tag)]
[padding до фиксированной длины]
```

**Конкретная реализация:**

```go
const (
    ShardFormatV2      = 0x02
    NonceSize          = 24  // XChaCha20-Poly1305
    AuthTagSize        = 16
    MaxShardDataSize   = 1024 // Фиксированный размер данных после padding
    V2HeaderSize       = 1 + 4 + NonceSize  // version + position + nonce
    V2TotalSize        = V2HeaderSize + MaxShardDataSize + AuthTagSize
)

func (s *Service) serializeMixedShardV2(shard *crypto.MixedShard, position uint32) ([]byte, error) {
    buf := make([]byte, V2TotalSize)

    // Header
    buf[0] = ShardFormatV2
    binary.BigEndian.PutUint32(buf[1:5], position)
    copy(buf[5:29], shard.Nonce)

    // Padded ciphertext (AEAD output уже включает auth tag)
    if len(shard.Ciphertext) > MaxShardDataSize+AuthTagSize {
        return nil, ErrShardTooLarge
    }
    copy(buf[29:], shard.Ciphertext)

    return buf, nil
}

func (s *Service) deserializeMixedShardV2(data []byte) (*StoredShard, error) {
    if len(data) < V2HeaderSize || data[0] != ShardFormatV2 {
        return nil, ErrInvalidFormat
    }

    return &StoredShard{
        Position:   binary.BigEndian.Uint32(data[1:5]),
        Nonce:      data[5:29],
        Ciphertext: data[29:], // Включает padding + auth tag
    }, nil
}
```

**Ключевые отличия от V1:**
- Бинарный формат (не текстовый с `|` разделителями)
- Нет ShardType, OriginalIndex, checksum, timestamp, ID
- Фиксированная длина = все шарды неотличимы по размеру
- Position — это позиция в storage, НЕ оригинальный индекс

### 3. Trial Decryption Recovery

**ВАЖНО:** Ключ деривируется от `realIdx` (оригинальный индекс real шарда), а не от `pos` (позиция в storage).

```go
func RecoverShards(bundleID string, totalShards, realCount int) [][]byte {
    recovered := make(map[uint32][]byte)
    usedPositions := make(map[int]bool) // Какие позиции уже matched

    // Для каждого real shard index (0..realCount-1)
    for realIdx := 0; realIdx < realCount; realIdx++ {
        // Деривируем ключ для этого real индекса
        key := hkdf.DeriveKeyForPosition(bundleID, uint32(realIdx))

        // Пробуем расшифровать каждый stored shard этим ключом
        for pos := 0; pos < totalShards; pos++ {
            if usedPositions[pos] {
                continue // Этот шард уже matched
            }

            shard := getStoredShard(bundleID, pos)

            // AEAD расшифровка — если ключ неверный, auth fail
            plaintext, err := aead.Open(shard.Data, key, shard.Nonce)
            if err == nil {
                // Успех! Шард на позиции `pos` — это real shard с индексом `realIdx`
                recovered[uint32(realIdx)] = plaintext
                usedPositions[pos] = true
                break
            }
            // Если fail — это либо decoy, либо другой real shard
        }
    }

    if len(recovered) != realCount {
        return nil, ErrInsufficientShards
    }

    return reassemble(recovered)
}
```

**Логика:**
- Real shard #0 зашифрован ключом `DeriveKeyForPosition(bundleID, 0)`
- Real shard #1 зашифрован ключом `DeriveKeyForPosition(bundleID, 1)`
- Decoy шарды зашифрованы случайными ключами (или ключами с большими индексами)
- При recovery: пробуем ключ для realIdx=0 на всех шардах, находим match, затем realIdx=1, и т.д.

### 4. Фиксированные лимиты по tier

| Tier | Real | Decoy | Total | Max Attempts |
|------|------|-------|-------|--------------|
| Basic | 64 | 32 | 96 | 6,144 |
| Standard | 64 | 64 | 128 | 8,192 |
| Premium | 64 | 96 | 160 | 10,240 |
| Elite | 64 | 128 | 192 | 12,288 |

DoS protection: `maxAttempts = totalShards × realCount`

---

## План реализации

### Phase 1: Key Derivation (P0)

**Файл:** `internal/crypto/hkdf.go`

- [ ] Добавить `DeriveKeyForPosition(bundleID string, position uint32) []byte`
- [ ] Deprecate `DeriveKeyForRealChar` / `DeriveKeyForDecoyChar`
- [ ] Salt persistence: добавить `NewHKDFManagerWithSalt(masterKey, salt []byte)`

### Phase 2: Storage Format v2 (P0)

**Файл:** `internal/service/service.go`

- [ ] `serializeMixedShardV2()` — без ShardType/OriginalIndex
- [ ] `deserializeMixedShardV2()` — парсинг нового формата
- [ ] Миграция: читать v1 и v2, писать только v2

### Phase 3: Asset Metadata (P0)

**Файл:** `internal/interfaces/service.go`

- [ ] Убрать `ShardIndexMap` из `LockedAsset`
- [ ] Добавить `TotalShards`, `RealCount`, `Salt`

### Phase 4: Trial Decryption (P1)

**Файл:** `internal/service/service.go`

- [ ] `RecoverWithTrialDecryption(asset *LockedAsset) ([]byte, error)`
- [ ] Parallel workers (runtime.NumCPU())
- [ ] Attempt counter с лимитом

### Phase 5: Integration (P2)

- [ ] `LockAsset`: использовать новый key derivation + format v2
- [ ] `UnlockAsset`: использовать trial decryption
- [ ] Генерировать и сохранять salt per-bundle

---

## Файлы для изменения

| Файл | Изменения |
|------|-----------|
| `internal/crypto/hkdf.go` | +DeriveKeyForPosition, +WithSalt, salt persistence |
| `internal/crypto/decoy.go` | +StoredShard, update comments |
| `internal/service/service.go` | serializeV2, LockAsset, UnlockAsset |
| `internal/interfaces/service.go` | -ShardIndexMap, +TotalShards/RealCount/Salt |

---

## Критерии приёмки

1. **Storage privacy:** `grep -r "ShardType\|OriginalIndex" serialized_data` = 0 результатов
2. **Trial decryption:** Recovery работает БЕЗ ShardIndexMap
3. **DoS protection:** Elite tier (192 шарда) recovers < 30 секунд
4. **No timing leak:** Все AEAD операции constant-time
5. **Salt persistence:** Restart → recovery работает
6. **Backwards compat:** Читаем v1 формат, пишем v2

---

## Test Helpers (нужно создать)

**Файл:** `internal/service/test_helpers.go`

```go
package service

import (
    "crypto/rand"
    "testing"
    "github.com/dueldanov/lockbox/v2/internal/crypto"
)

func newTestService(t *testing.T) *Service {
    t.Helper()
    masterKey := make([]byte, 32)
    rand.Read(masterKey)
    svc, _ := NewService(ServiceConfig{MasterKey: masterKey, Tier: TierStandard})
    return svc
}

func createTestRealShard(t *testing.T, index uint32) *crypto.MixedShard {
    t.Helper()
    data := make([]byte, 64)
    rand.Read(data)
    return &crypto.MixedShard{
        CharacterShard: crypto.CharacterShard{Index: index, Total: 10, Data: data},
        ShardType:      crypto.DecoyTypeReal,
        OriginalIndex:  index,
    }
}

func createTestDecoyShard(t *testing.T, index uint32) *crypto.MixedShard {
    t.Helper()
    data := make([]byte, 64)
    rand.Read(data)
    return &crypto.MixedShard{
        CharacterShard: crypto.CharacterShard{Index: index + 1000, Total: 10, Data: data},
        ShardType:      crypto.DecoyTypeDecoy,
        OriginalIndex:  index,
    }
}

func createTestAssetWithShards(t *testing.T, realCount, totalCount int) *LockedAsset {
    t.Helper()
    salt := make([]byte, 32)
    rand.Read(salt)
    return &LockedAsset{
        ID: "test-asset-id", TotalShards: totalCount, RealCount: realCount, Salt: salt, Tier: TierStandard,
    }
}

func deriveTestKey(t *testing.T, bundleID string, position uint32) []byte {
    t.Helper()
    masterKey := make([]byte, 32)
    salt := make([]byte, 32)
    hkdf, _ := crypto.NewHKDFManagerWithSalt(masterKey, salt)
    defer hkdf.Clear()
    key, _ := hkdf.DeriveKeyForPosition(bundleID, position)
    return key
}
```

---

## Риски

| Риск | Mitigation |
|------|------------|
| Breaking existing data | Version marker, read v1+v2, lazy migration |
| Performance regression | Parallel workers, benchmarks |
| Subtle crypto bugs | Existing crypto tests + new boundary tests |
| Test helpers missing | Create test_helpers.go first |
