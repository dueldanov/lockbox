# Модуль: lockscript

## Назначение

Скриптовый язык для условий разблокировки активов:
- Lexer/Parser для DSL
- VM с bytecode
- 9 built-in функций
- Ed25519 signature verification

## Файлы

| Файл | Назначение |
|------|------------|
| `lexer.go` | Токенизация скриптов |
| `parser.go` | Построение AST |
| `ast.go` | Типы узлов AST |
| `vm.go` | Виртуальная машина |
| `opcodes.go` | 27+ операций bytecode |
| `builtins.go` | 9 встроенных функций |
| `engine.go` | Высокоуровневый API |
| `signing.go` | Ed25519 подписи |
| `cache.go` | Кэш скомпилированных скриптов |

## Built-in функции

| Функция | Аргументы | Описание |
|---------|-----------|----------|
| `now()` | - | Текущий Unix timestamp |
| `after(ts)` | int64 | true если time > ts |
| `before(ts)` | int64 | true если time < ts |
| `sha256(data)` | string | SHA256 хэш |
| `verify_sig(pk, msg, sig)` | string×3 | Ed25519 verify |
| `require_sigs(sigs, n)` | []sig, int | n-of-m подписи |
| `check_geo(loc)` | string | Проверка региона |
| `min(a, b, ...)` | int... | Минимум |
| `max(a, b, ...)` | int... | Максимум |

## OpCodes

```go
const (
    // Stack
    OpPush, OpPop, OpDup, OpSwap

    // Memory
    OpLoad, OpStore

    // Arithmetic
    OpAdd, OpSub, OpMul, OpDiv, OpMod

    // Comparison
    OpEq, OpNe, OpLt, OpGt, OpLe, OpGe

    // Logical
    OpAnd, OpOr, OpNot

    // Control flow
    OpIf, OpElse, OpEndIf, OpJump, OpJumpIf, OpReturn

    // Functions
    OpCall, OpCallBuiltin

    // Special
    OpTimeCheck, OpSigVerify, OpHashCheck, OpGeoCheck

    // Constants
    OpTrue, OpFalse, OpNull
)
```

## Паттерны использования

### Компиляция и выполнение скрипта

```go
// Создать engine
engine := NewEngine(nil, 65536, 5*time.Second)
engine.RegisterBuiltinFunctions()

// Компилировать
script := `after(unlock_time) && verify_sig(owner, message, signature)`
compiled, err := engine.CompileScript(ctx, script)
if err != nil {
    return err
}

// Выполнить с контекстом
execCtx := NewContext()
execCtx.Set("unlock_time", asset.UnlockTime.Unix())
execCtx.Set("owner", ownerPubKey)
execCtx.Set("message", assetID)
execCtx.Set("signature", sig)

result, err := engine.Execute(compiled, execCtx)
if err != nil {
    return err
}
if !result.(bool) {
    return ErrUnauthorized
}
```

### Ed25519 Signing

```go
// Генерация ключей
privKey, pubKey := GenerateKeyPair()

// Подписание
signature := SignMessage(privKey, message)

// Верификация
valid, err := VerifyEd25519Signature(
    PublicKeyHex(pubKey),
    message,
    hex.EncodeToString(signature),
)
```

### Примеры скриптов

```js
// Простой time-lock
after(1700000000)

// Time-lock + owner signature
after(unlock_time) && verify_sig(owner, asset_id, signature)

// Multi-sig (2-of-3)
require_sigs(signatures, 2)

// Geo-restriction
check_geo("us-east") || check_geo("eu-west")

// Complex condition
after(unlock_time) && (
    verify_sig(owner, msg, sig) ||
    require_sigs(emergency_sigs, 2)
)
```

## Зависимости

- **От:** `crypto` (для signing)
- **Используется в:** `service` (InitializeCompiler, UnlockAsset)

## Тесты

```bash
go test ./internal/lockscript/... -v

# Тесты подписей
go test -run TestVerifyEd25519Signature
go test -run TestSignMessage
```

## Важные детали

1. **InitializeCompiler = заглушка**
   - В `service.go:328` просто `return nil`
   - TODO: интегрировать engine

2. **LockScript не исполняется**
   - В LockAsset сохраняется как строка
   - В UnlockAsset не проверяется
   - TODO: добавить execution в UnlockAsset

3. **125 функций в пакете**
   - Полноценный VM с control flow
   - Caching скомпилированных скриптов

4. **Ed25519 НЕ secp256k1**
   - IOTA использует Ed25519
   - Совместимо с iota.go
