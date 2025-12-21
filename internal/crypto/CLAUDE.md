# Модуль: crypto

## Назначение

Криптографические примитивы для LockBox:
- HKDF key derivation (purpose-specific ключи)
- ChaCha20-Poly1305 шифрование шардов
- Decoy generation (фейковые шарды для маскировки)
- ZKP commitments (SHA256 с domain separation)
- KeyStore (персистентное хранение master key)

## Файлы

| Файл | Назначение |
|------|------------|
| `hkdf.go` | HKDF-SHA256 key derivation |
| `encrypt.go` | ShardEncryptor, CharacterShard |
| `decoy.go` | DecoyGenerator, ShardMixer |
| `zkp.go` | ZKPManager, commitments |
| `keystore.go` | Файловое хранение master key |
| `memory.go` | Безопасная очистка памяти |

## Ключевые типы

```go
// HKDFManager управляет деривацией ключей
type HKDFManager struct {
    masterKey []byte  // 32 bytes
    salt      []byte  // random per session
}

// CharacterShard зашифрованный фрагмент данных
type CharacterShard struct {
    ID        uint32  // уникальный ID
    Index     uint32  // позиция в последовательности
    Total     uint32  // общее количество шардов
    Data      []byte  // зашифрованные данные
    Nonce     []byte  // 12 bytes for ChaCha20
    Checksum  []byte  // integrity check
    Timestamp int64   // время создания
}

// DecoyGenerator создаёт фейковые шарды
type DecoyGenerator struct{}

// ShardMixer смешивает real и decoy шарды
type ShardMixer struct{}
```

## Паттерны использования

### HKDF Key Derivation

```go
// Создание manager с master key
masterKey := make([]byte, 32)
rand.Read(masterKey)

hkdf, err := NewHKDFManager(masterKey)
if err != nil {
    return err
}
defer hkdf.Clear() // ВАЖНО: очистить память

// Деривация ключа для конкретной цели
purpose := "shard-encrypt"
key := hkdf.DeriveKey(purpose, shardIndex)

// Разные purpose = разные ключи
key1 := hkdf.DeriveKey("shard-encrypt", 0)
key2 := hkdf.DeriveKey("metadata", 0)
// key1 != key2
```

### Шифрование данных

```go
// Создание encryptor
encryptor, err := NewShardEncryptor(masterKey, 4096) // 4KB shards
if err != nil {
    return err
}

// Зашифровать данные
shards, err := encryptor.EncryptData(plaintext)

// Расшифровать обратно
decrypted, err := encryptor.DecryptShards(shards)
```

### Decoy Generation

```go
// Создать generator
gen := NewDecoyGenerator()

// Сгенерировать decoys (ratio = 1.0 = 100% от real)
decoyRatio := 1.0
decoys := gen.GenerateDecoyShards(realShards, decoyRatio)

// Смешать
mixer := NewShardMixer()
mixed, indexMap := mixer.Mix(realShards, decoys)

// Позже извлечь только real
realOnly := mixer.ExtractReal(mixed, indexMap)
```

### ZKP Commitments

```go
zkp := NewZKPManager()

// Создать ownership proof
proof, err := zkp.GenerateOwnershipProof(assetID, ownerSecret)

// Верифицировать
err := zkp.VerifyOwnershipProof(proof)

// Commitment для адреса (детерминированный)
addr := CalculateAddress(secret, index)
```

### KeyStore

```go
// Создать store
store, err := NewKeyStore("/path/to/keys")

// Загрузить или сгенерировать
masterKey, err := store.LoadOrGenerate()
defer ClearBytes(masterKey)

// Проверить существование
exists := store.Exists()

// Удалить
err := store.Delete()
```

## Безопасность памяти

```go
// ВСЕГДА очищай чувствительные данные
defer ClearBytes(masterKey)
defer hkdf.Clear()

// TimedClear для автоматической очистки
tc := NewTimedClear()
tc.Schedule("key-id", sensitiveData, 5*time.Minute)
```

## Зависимости

- **От:** `interfaces` (только типы)
- **Используется в:** `service`, `lockscript`, `verification`

## Тесты

```bash
go test ./internal/crypto/... -v

# Конкретные тесты
go test -run TestHKDFManager
go test -run TestDecoyGenerator
go test -run TestShardMixer
```

## Важные детали

1. **Salt не персистентный** - при рестарте генерируется новый
   - Для persistence нужно сохранять salt с данными (TODO P2)

2. **Decoys неотличимы** - тот же размер, та же энтропия
   - Проверяется в TestDecoyIndistinguishability

3. **Domain separation в ZKP**
   - Разные prefix для разных типов commitments
   - `"LockBox:address:"`, `"LockBox:commitment:"`

4. **ChaCha20-Poly1305** - AEAD
   - Nonce 12 bytes, уникальный для каждого шарда
   - Poly1305 MAC для integrity
