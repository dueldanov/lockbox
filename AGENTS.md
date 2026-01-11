# AGENTS.md

## Build & Test Commands
- **Build:** `./build.sh` or `go build -o lockbox-node`
- **Build with RocksDB:** `go build -tags rocksdb -o lockbox-node`
- **Test all:** `go test ./...`
- **Test single:** `go test -v -run TestName ./path/to/package`
- **Test (skip integration):** `go test $(go list ./... | grep -v integration-tests)`
- **Lint:** `golangci-lint run --timeout=10m`

## Code Style
- **Go version:** 1.22
- **Imports:** 3 groups separated by blank lines: stdlib, external, internal (`github.com/dueldanov/lockbox/v2/...`)
- **Naming:** CamelCase exported, camelCase unexported; `Cfg` prefix for config keys; `Err` prefix for errors
- **Errors:** Use `errors.New()` for simple errors, `fmt.Errorf("context: %w", err)` for wrapping
- **Receivers:** Single lowercase letter (e.g., `func (m *Manager) Method()`)
- **Context:** First parameter when needed: `func Foo(ctx context.Context, ...)`
- **Mutex:** Place near protected data, defer unlock immediately after lock
- **Comments:** Complete sentences ending with periods; function comments start with function name
- **Testing:** Use `testify/require` for assertions, `t.Run()` for sub-tests
