# План исправления тестов LockBox

## Статус: 2026-01-20

## Текущее состояние тестов

### ✅ Проходящие модули

| Модуль | Статус | Примечания |
|--------|--------|-----------|
| `internal/crypto` | ✅ PASS | Все AEAD, HKDF, ZKP, Decoy тесты работают |
| `internal/lockscript` | ✅ PASS | VM, Parser, Builtins - все проходят |
| `internal/verification` | ✅ PASS | Node selection, Token rotation, Rate limiter OK |
| `internal/payment` | ✅ PASS | Payment processing работает |
| `internal/b2b` | ✅ PASS | B2B API тесты OK |
| `internal/logging` | ✅ PASS | |
| `pkg/*` | ✅ PASS | Все базовые пакеты OK |
| `tests/integration` | ✅ PASS | Integration тесты работают |

### ❌ Падающие тесты

#### 1. Critical Security Issues (internal/service)

**CRIT-001: Payment Double-Spend Race Condition**
- **Файл:** `internal/service/security_bugs_test.go:32`
- **Тест:** `TestPaymentDoubleSpend_RaceCondition`
- **Проблема:** Платёжный токен проверяется ПЕРЕД тем как пометить "использованным", что позволяет 50 параллельных запросов использовать один токен
- **Текущий результат:** 50/50 concurrent verifications succeeded
- **Ожидается:** Только 1/50 должна пройти
- **Критичность:** 🔴 CRITICAL - позволяет заплатить 1 раз и разблокировать много раз

**Решение:**
```go
// internal/service/service.go:210 (UnlockAsset)

// ❌ ТЕКУЩИЙ КОД (уязвимый):
// 1. Проверить payment token
verifyResp, err := s.paymentProcessor.VerifyPayment(ctx, verifyReq)
if !verifyResp.Valid {
    return nil, ErrInvalidPayment
}

// 2. Выполнить unlock (долгая операция)
// ... расшифровка, проверки ...

// 3. Пометить payment как использованный (СЛИШКОМ ПОЗДНО!)
err = s.paymentProcessor.MarkPaymentUsed(ctx, req.PaymentToken)

// ✅ ПРАВИЛЬНЫЙ КОД:
// 1. Атомарно проверить И пометить как использованный ОДНОВРЕМЕННО
marked, err := s.paymentProcessor.VerifyAndMarkUsed(ctx, verifyReq)
if !marked {
    return nil, ErrInvalidPayment // Токен уже использован или невалиден
}

// 2. Теперь выполнить unlock
// ... расшифровка, проверки ...
```

**Файлы для изменения:**
- `internal/payment/processor.go` - добавить `VerifyAndMarkUsed()` с mutex
- `internal/service/service.go:210` - изменить порядок вызовов

---

**Rate Limiter Bypass (100x amplification)**
- **Файл:** `internal/service/security_bugs_test.go:242`
- **Тест:** `TestRateLimiter_PerAssetNotPerUser`
- **Проблема:** Rate limiter работает per-asset вместо per-user. Атакующий может создать 100 активов и получить 500 попыток/мин вместо 5.
- **Текущий результат:** 500 attempts/min (5 per asset × 100 assets)
- **Ожидается:** 5 attempts/min per user (owner address)
- **Критичность:** 🟡 MEDIUM - позволяет brute-force атаки

**Решение:**
```go
// internal/service/service.go:210 (UnlockAsset)

// ❌ ТЕКУЩИЙ КОД (уязвимый):
allowed, err := s.rateLimiter.Allow(req.AssetID) // PER-ASSET!

// ✅ ПРАВИЛЬНЫЙ КОД:
// Использовать owner address вместо assetID
asset, err := s.storageManager.GetAsset(ctx, req.AssetID)
ownerID := asset.OwnerAddress.String()
allowed, err := s.rateLimiter.Allow(ownerID) // PER-USER!
```

**Файлы для изменения:**
- `internal/service/service.go:210` - изменить ключ для rate limiter
- Добавить тест на multiple assets, same user

---

#### 2. Integration Tests (IOTA Framework Legacy)

**Проблема:** Старые IOTA framework тесты падают
- `integration-tests/` - FAIL (legacy IOTA node tests)
- `integration-tests/tester/tests/autopeering` - FAIL
- `integration-tests/tester/tests/common` - FAIL
- `integration-tests/tester/tests/migration` - FAIL
- `integration-tests/tester/tests/snapshot` - FAIL
- `integration-tests/tester/tests/value` - FAIL

**Причина:** Эти тесты относятся к legacy IOTA node framework, не к LockBox логике

**Решение:**
1. Переместить в `integration-tests/legacy/`
2. Добавить skip flag: `go test -tags=legacy`
3. Сфокусироваться на LockBox-specific integration тестах в `tests/integration/`

**Файлы для изменения:**
- Переместить `integration-tests/tester/tests/*` → `integration-tests/legacy/`
- Добавить build tags `// +build legacy`
- Обновить CI/CD чтобы skip legacy тесты

---

## План исправления (по приоритету)

### Фаза 1: Critical Security Fixes (Приоритет 🔴)

**Задачи:**

1. **Исправить CRIT-001: Payment Double-Spend**
   - [ ] Добавить метод `VerifyAndMarkUsed()` в `internal/payment/processor.go`
   - [ ] Добавить mutex для атомарности проверки+пометки
   - [ ] Изменить `UnlockAsset()` для использования нового метода
   - [ ] Убедиться что `TestPaymentDoubleSpend_RaceCondition` PASS

2. **Исправить Rate Limiter Bypass**
   - [ ] Изменить ключ rate limiter с assetID на ownerAddress
   - [ ] Добавить тест на multiple assets, same owner
   - [ ] Убедиться что `TestRateLimiter_PerAssetNotPerUser` PASS

**Время:** 2-3 часа
**Критичность:** Блокирует production release

---

### Фаза 2: Integration Tests Cleanup (Приоритет 🟡)

**Задачи:**

1. **Отделить legacy IOTA tests**
   - [ ] Создать `integration-tests/legacy/` directory
   - [ ] Переместить legacy тесты туда
   - [ ] Добавить build tags `// +build legacy`
   - [ ] Обновить CI/CD pipeline

2. **Добавить LockBox integration тесты**
   - [ ] End-to-end Lock → Unlock flow
   - [ ] Multi-sig emergency unlock flow
   - [ ] Tier capabilities verification
   - [ ] LockScript execution integration

**Время:** 4-6 часов
**Критичность:** Важно для CI/CD, но не блокирует функциональность

---

### Фаза 3: Missing Unit Tests (Приоритет 🟢)

**Текущее покрытие:**
- ✅ Crypto components: ~90%
- ✅ LockScript: ~85%
- ✅ Verification: ~80%
- ⚠️ Service layer: ~60%
- ❌ Storage: ~40%

**Недостающие тесты:**

1. **Service layer**
   - [ ] `LockAsset()` с decoy generation
   - [ ] `LockAsset()` с tier capabilities
   - [ ] `UnlockAsset()` с multi-sig
   - [ ] `UnlockAsset()` с LockScript execution

2. **Storage layer**
   - [ ] Shard persistence
   - [ ] Index map storage/retrieval
   - [ ] Asset metadata encryption
   - [ ] Storage failure recovery

3. **Crypto components**
   - [ ] Decoy mixer edge cases
   - [ ] HKDF key derivation limits
   - [ ] ZKP proof verification edge cases

**Время:** 6-8 часов
**Критичность:** Улучшает надёжность, но не критично

---

## Детальные команды

### Запуск тестов по категориям

```bash
# Только security тесты
go test ./internal/service -run Security -v

# Только unit тесты (без integration)
go test ./internal/... -v

# Только integration тесты
go test ./tests/integration/... -v

# Legacy тесты (когда переместим)
go test ./integration-tests/legacy/... -tags=legacy -v

# Полный набор (без legacy)
go test ./... -v
```

### Проверка покрытия

```bash
# Генерация coverage report
go test ./internal/... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Проверка coverage по модулям
go test ./internal/crypto -cover
go test ./internal/service -cover
go test ./internal/verification -cover
```

### CI/CD интеграция

```yaml
# .github/workflows/tests.yml
name: Tests
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run unit tests
        run: go test ./internal/... -v

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security tests
        run: go test ./internal/service -run Security -v

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run integration tests
        run: go test ./tests/integration/... -v
```

---

## Критерии успеха

### Обязательные (Must Have)

- [x] `internal/crypto` - 100% PASS ✅
- [x] `internal/lockscript` - 100% PASS ✅
- [x] `internal/verification` - 100% PASS ✅
- [ ] `internal/service` - 100% PASS (сейчас 2 security tests FAIL)
- [ ] Security tests - 100% PASS (сейчас 2/2 FAIL)

### Желательные (Should Have)

- [ ] Integration tests - 100% PASS (отделить legacy)
- [ ] Coverage - минимум 80% для всех модулей
- [ ] CI/CD pipeline настроен
- [ ] Documentation обновлена

### Опциональные (Nice to Have)

- [ ] Performance benchmarks
- [ ] Fuzzing tests для crypto
- [ ] Property-based testing для LockScript

---

## Риски и зависимости

### Риски

1. **CRIT-001 fix может сломать существующий code** - требуется careful testing
2. **Rate limiter change может повлиять на UX** - нужно балансировать security и usability
3. **Legacy tests могут быть нужны для IOTA integration** - проверить перед удалением

### Зависимости

1. Payment processor refactor → Service layer changes
2. Rate limiter fix → Verification layer changes
3. Integration tests → Все компоненты должны работать

---

## Следующие шаги

1. **Немедленно:** Исправить CRIT-001 (Payment Double-Spend)
2. **Сегодня:** Исправить Rate Limiter bypass
3. **Эта неделя:** Cleanup integration tests
4. **Следующая неделя:** Добавить missing unit tests

---

## Контрольный список перед production

- [ ] Все security tests PASS
- [ ] Coverage минимум 80%
- [ ] CI/CD pipeline зелёный
- [ ] Security audit пройден
- [ ] Load testing выполнен
- [ ] Docs обновлены
