# Модуль: verification

## Назначение

Система верификации активов:
- Node selection (географический)
- Token management (rotation)
- Rate limiting (5 req/min)
- Retry mechanism

## Файлы

| Файл | Назначение |
|------|------------|
| `verifier.go` | Главный Verifier |
| `selector.go` | NodeSelector |
| `token_manager.go` | TokenManager |
| `rate_limiter.go` | Rate limiting |
| `retry.go` | RetryManager |
| `types.go` | VerificationRequest/Result |

## Ключевые типы

```go
// Verifier выполняет верификацию активов
type Verifier struct {
    log          *logger.Logger
    nodeSelector *NodeSelector
    tokenManager *TokenManager
    storage      StorageManager // interface!
}

// NodeSelector выбирает ноды для верификации
type NodeSelector struct {
    nodes       []NodeInfo
    minRegions  int // 3 для Standard
}

// NodeInfo информация о ноде
type NodeInfo struct {
    ID        string
    Endpoint  string
    Region    string
    Latency   time.Duration
    Available bool
}

// TokenManager управляет токенами
type TokenManager struct {
    rotationInterval  time.Duration
    validityWindow    time.Duration
    currentToken      *VerificationToken
}

// RateLimiter ограничивает запросы
type RateLimiter struct {
    buckets   map[string]*TokenBucket
    maxTokens int           // 5
    refillRate time.Duration // 12s (= 5/min)
}
```

## Паттерны использования

### Node Selection

```go
selector := NewNodeSelector(log)

// Зарегистрировать ноды
selector.RegisterNode(NodeInfo{
    ID:       "node-1",
    Region:   "us-east",
    Endpoint: "https://node1.example.com:443",
})

// Выбрать ноды для верификации (min 3 региона)
nodes, err := selector.SelectNodes(ctx, TierStandard, []string{"us-east", "eu-west"})
```

### Token Management

```go
tokenMgr := NewTokenManager(log, 24*time.Hour, 1*time.Hour)

// Запустить rotation
ctx, cancel := context.WithCancel(context.Background())
go tokenMgr.Start(ctx)

// Получить текущий токен
token := tokenMgr.GetCurrentToken()

// Валидировать
valid := tokenMgr.ValidateToken(tokenID)
```

### Rate Limiting

```go
limiter := NewRateLimiter(5, 12*time.Second) // 5 req/min

// Проверить лимит
allowed, err := limiter.Allow("user-123")
if !allowed {
    retryAfter := limiter.RetryAfter("user-123")
    return RateLimitError{RetryAfter: retryAfter}
}

// Статистика
stats := limiter.GetStats()
// {ActiveUsers: 10, MaxTokens: 5, RefillRate: 12s}
```

### Retry Mechanism

```go
retryMgr := NewRetryManager(log, DefaultRetryConfig())

err := retryMgr.RetryWithBackoff(ctx, "operation-id", func(ctx context.Context) error {
    // попытка операции
    return doVerification()
})
// Автоматически повторяет с exponential backoff
```

### Полный flow верификации

```go
verifier := NewVerifier(log, nodeSelector, tokenManager, storageAdapter)

req := &VerificationRequest{
    AssetID:   assetID,
    Tier:      TierStandard,
    Requester: ownerAddr,
    Nonce:     nonce,
}

result, err := verifier.VerifyAsset(ctx, req)
if err != nil {
    return err
}
// result.Verified, result.Nodes, result.Timestamp
```

## Зависимости

- **От:** `interfaces`, `crypto`
- **Используется в:** `service`

## Import Cycle проблема

```go
// ❌ verification_test.go НЕПРАВИЛЬНО
import "github.com/dueldanov/lockbox/v2/internal/service"

// На line 16 используется:
lockbox.TierStandard  // ← несуществующий импорт!

// ✅ ПРАВИЛЬНО - использовать interfaces
import "github.com/dueldanov/lockbox/v2/internal/interfaces"

// И заменить на:
interfaces.TierStandard
```

## Тесты

```bash
# ПРОБЛЕМА: import cycle
go test ./internal/verification/... -v
# FAIL - import cycle not allowed in test

# Решение: исправить verification_test.go
```

## Важные детали

1. **StorageManager = interface**
   - Используется `interfaces.StorageProvider`
   - Избегает import cycle с service

2. **Rate limiter in-memory**
   - Сбрасывается при рестарте
   - OK для security (nonce/signature защищают)

3. **Triple verification**
   - Standard+ требует 3 ноды
   - Из разных регионов

4. **Token rotation**
   - Каждые 24h новый токен
   - Старый валиден 1h после rotation
