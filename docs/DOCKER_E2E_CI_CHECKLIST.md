# Docker e2e CI Checklist

Date: 2026-02-06

## 1) Host prerequisites
- Linux/macOS runner with Docker daemon access.
- `docker info` works without `sudo` errors.
- `docker compose version` is available.
- At least ~20 GB free disk space for images/logs.

## 2) Preflight commands
```bash
docker info
docker compose version
mkdir -p integration-tests/logs
docker build -f Dockerfile -t lockbox:dev .
docker build https://github.com/iotaledger-archive/chrysalis-tools.git#master:wfmock -t wfmock:latest
docker pull iotaledger/inx-coordinator:1.0-rc
docker pull iotaledger/inx-indexer:1.0-rc
```

## 3) Run matrix locally (same as CI job)
```bash
set -euo pipefail
for TEST_NAME in common value migration snapshot autopeering; do
  echo "== Running ${TEST_NAME} =="
  TEST_NAME="${TEST_NAME}" docker compose \
    -f integration-tests/tester/docker-compose.yml \
    up --abort-on-container-exit --exit-code-from tester --build

  docker logs tester > "integration-tests/logs/${TEST_NAME}_tester.log" 2>&1 || true
  ./scripts/check-test-containers.sh "test_" 400 > "integration-tests/logs/${TEST_NAME}_containers.log" 2>&1 || true

  TEST_NAME="${TEST_NAME}" docker compose \
    -f integration-tests/tester/docker-compose.yml \
    down -v --remove-orphans || true
done
```

## 4) If `value` test fails with tips timeout
- Symptom: `Condition never satisfied` in `integration-tests/tester/tests/value/value_test.go`.
- Collect diagnostics:
```bash
docker logs tester --tail=500
./scripts/check-test-containers.sh "test_" 500
```
- Confirm you are running latest branch state that includes tip-parent fallback logic.

## 5) GitHub Actions checklist
- Workflow file: `.github/workflows/integration_tests.yml`
- Must include:
  - `strategy.matrix.test_name: [common, value, migration, snapshot, autopeering]`
  - `docker info` + `docker compose version` sanity step
  - image build/pull steps (`lockbox:dev`, `wfmock`, `inx-coordinator`, `inx-indexer`)
  - per-matrix run:
    - `TEST_NAME="${TEST_NAME}" docker compose ... up --abort-on-container-exit --exit-code-from tester --build`
  - `if: always()` diagnostics and `docker compose down -v --remove-orphans`
  - artifact upload from `integration-tests/logs`

## 6) Fast rerun command (single case)
```bash
TEST_NAME=value docker compose \
  -f integration-tests/tester/docker-compose.yml \
  up --abort-on-container-exit --exit-code-from tester --build
```
