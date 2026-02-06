#!/usr/bin/env bash
set -euo pipefail

pattern="${1:-test_}"
tail_lines="${2:-200}"

echo "== Containers matching: ${pattern} =="
docker ps -a --format "{{.Names}}\t{{.Status}}\t{{.Image}}" | rg "${pattern}" || true
echo

echo "== Exit codes / OOMKilled =="
while read -r name; do
  [ -z "$name" ] && continue
  echo ">> $name"
  docker inspect -f 'OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}} FinishedAt={{.State.FinishedAt}}' "$name" || true
done < <(docker ps -a --format "{{.Names}}" | rg "${pattern}")

echo
echo "== Tail logs (${tail_lines} lines) for exited containers =="
while read -r name; do
  [ -z "$name" ] && continue
  exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$name" 2>/dev/null || echo 0)"
  if [ "$exit_code" != "0" ]; then
    echo "---- $name (exit=$exit_code) ----"
    docker logs --tail="${tail_lines}" "$name" || true
    echo
  fi
done < <(docker ps -a --format "{{.Names}}" | rg "${pattern}")
