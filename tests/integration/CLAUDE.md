# Модуль: tests/integration

## Назначение

Интеграционные и E2E тесты LockBox.

## Файлы

| Файл | Назначение |
|------|------------|
| `e2e_persistence_test.go` | E2E тесты Milestone 1 |
| `service_test.go` | Интеграция crypto + service |

## Тестовые сценарии

### e2e_persistence_test.go

```go
// TestE2E_ShardEncryptionPersistence
// Проверяет: encrypt → serialize → deserialize → decrypt
// Результат: данные совпадают

// TestE2E_DecoyMixingPersistence
// Проверяет: real + decoy → mix → persist → load → extract real
// Результат: извлечённые real совпадают с оригинальными

// TestE2E_HKDFKeyDerivation
// Проверяет: одинаковые inputs = одинаковые keys
// Проверяет: разные indexes = разные keys
// Проверяет: разные purposes = разные keys

// TestE2E_FullMilestone1Verification
// - Encryption_Works
// - Data_Persistence
// - Basic_Auth_Signature
// - ZKP_SHA256_Hashing
```

### service_test.go

```go
// TestCryptoIntegration
// - HKDF_PurposeSpecificKeys
// - ShardEncryption
// - DecoyGeneration (Basic/Standard/Premium/Elite)
// - ShardMixing

// TestRateLimiterIntegration
// - BasicRateLimit
// - RemainingCount
// - RetryAfter
// - Stats

// TestTierCapabilities
// Проверяет ShardCopies, DecoyRatio для каждого тира
```

## Паттерны тестирования

### Setup для crypto тестов

```go
func setupCrypto(t *testing.T) (*crypto.ShardEncryptor, *crypto.HKDFManager) {
    masterKey := make([]byte, 32)
    for i := range masterKey {
        masterKey[i] = byte(i)
    }

    hkdf, err := crypto.NewHKDFManager(masterKey)
    require.NoError(t, err)
    t.Cleanup(func() { hkdf.Clear() })

    encryptor, err := crypto.NewShardEncryptor(masterKey, 4096)
    require.NoError(t, err)

    return encryptor, hkdf
}
```

### Тест roundtrip

```go
func TestRoundtrip(t *testing.T) {
    original := []byte("secret data")

    // Encrypt
    shards, err := encryptor.EncryptData(original)
    require.NoError(t, err)

    // Serialize
    serialized, err := serializeShards(shards)
    require.NoError(t, err)

    // Deserialize
    loaded, err := deserializeShards(serialized)
    require.NoError(t, err)

    // Decrypt
    decrypted, err := encryptor.DecryptShards(loaded)
    require.NoError(t, err)

    // Compare
    require.Equal(t, original, decrypted)
}
```

### Тест decoy mixing

```go
func TestDecoyMixing(t *testing.T) {
    realShards := createTestShards(5)

    gen := crypto.NewDecoyGenerator()
    decoys := gen.GenerateDecoyShards(realShards, 1.0) // 100%

    mixer := crypto.NewShardMixer()
    mixed, indexMap := mixer.Mix(realShards, decoys)

    // Mixed должен содержать real + decoy
    require.Len(t, mixed, len(realShards)+len(decoys))

    // Extract только real
    extracted := mixer.ExtractReal(mixed, indexMap)
    require.Len(t, extracted, len(realShards))

    // Проверить что данные совпадают
    for i, shard := range extracted {
        require.Equal(t, realShards[i].Data, shard.Data)
    }
}
```

## Запуск

```bash
# Все интеграционные тесты
go test ./tests/integration/... -v

# Только E2E
go test ./tests/integration/... -v -run TestE2E

# Milestone 1 verification
go test ./tests/integration/... -v -run TestE2E_FullMilestone1Verification

# С покрытием
go test ./tests/integration/... -v -cover
```

## Ограничения текущих тестов

1. **Тестируют компоненты в изоляции**
   - Crypto работает
   - Rate limiter работает
   - Но не через реальный Service

2. **Salt не персистентный**
   - Тест отмечает: "Full process restart requires salt persistence (P2 feature)"

3. **Нет теста полного pipeline**
   - LockAsset → wait → UnlockAsset с реальным сервисом
   - TODO: добавить full_pipeline_test.go

## TODO тесты

```go
// tests/integration/full_pipeline_test.go

func TestFullPipeline(t *testing.T) {
    svc := setupRealService(t)

    // 1. Lock с LockScript
    lockResp, err := svc.LockAsset(ctx, &LockAssetRequest{
        OwnerAddress: addr,
        LockDuration: time.Second,
        LockScript:   "after(unlock_time)",
    })
    require.NoError(t, err)

    // 2. Проверить что decoys созданы
    // ...

    // 3. Wait
    time.Sleep(2 * time.Second)

    // 4. Unlock
    unlockResp, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
        AssetID: lockResp.AssetID,
    })
    require.NoError(t, err)

    // 5. Verify
    require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}
```
