# Production-Ready Plan (3+3 DAG Rule)

## Коротко
План выполняется по правилу: **сначала тест (должен падать), потом реализация, затем повторный тест**.
Никакой подгонки тестов под код. Только реальные кейсы.
Переход к следующему пункту — только после устойчивого прохождения теста.

---

## Важные изменения (структуры/параметры)
- **DAG параметры**:
  - `MinPreviousRefs = 3`
  - `MinFutureApprovals = 3`
- **ApprovalState**:
  - `ApprovalCount`
  - `ConfirmedAt *int64`
  - `Approvers` выводятся из reverse-index (children storage)
- **ApprovalIndex (reverse-index)**:
  - `children storage` (parent -> children)
- **Config**:
  - `dag.min_previous_refs`
  - `dag.min_future_approvals`

---

## Пункт 1 — Требования (единый стандарт 3+3)
**Тест (должен падать):**
- Проверить требования: найти все места, где "2 previous" и "3 future" и убедиться, что они конфликтуют.

**Реализация:**
- Переписать требования: **3 previous + 3 future для всех транзакций**.

**Проверка:**
- Повторный анализ требований — конфликтов нет.

**Если падает:**
- Найти документ с устаревшей формулировкой и исправить.

---

## Пункт 2 — Валидация 3 previous (consensus)
**Тест (должен падать):**
- Транзакция с 2 refs должна быть отвергнута (сейчас логики нет).

**Реализация:**
- Ввести правило: **ровно 3 refs**.

**Проверка:**
- 2 refs → reject
- 3 refs → accept

**Если падает:**
- Проверить маршрут: `validateBlockStructure` → `checkConsensusRules` → submit.

---

## Пункт 3 — Approval threshold (3 future approvals)
**Тест (должен падать):**
- Tx + 2 approvals → не confirmed
- Tx + 3 approvals → confirmed

**Реализация:**
- Ввести approval tracking и threshold **>=3**.

**Проверка:**
- Подтверждение на 3-м approval.

**Если падает:**
- Проверить дубликаты approvals и race conditions.

---

## Пункт 4 — Approval Index (reverse mapping)
**Тест (должен падать):**
- При добавлении tx T, parents A/B/C не получают +1 approval.

**Реализация:**
- Добавить ApprovalIndex и атомарные обновления.

**Проверка:**
- A/B/C получают approvals
- confirmed при 3 approvals

**Если падает:**
- Проверить порядок записи и атомарность.

---

## Пункт 5 — Tip Selection = 3 tips
**Тест (должен падать):**
- Алгоритм возвращает 2 tips или дубликаты.

**Реализация:**
- Выбирать **3 уникальных tips**.

**Проверка:**
- Ровно 3 уникальных tips.

**Если падает:**
- Проверить tip pool и фильтр дубликатов.

---

## Пункт 6 — Signature coverage
**Тест (должен падать):**
- Подпись не включает 3-й ref → reject.

**Реализация:**
- TransactionEssence.Payload содержит `TaggedData` с tag `lockbox.parents.v1`,
  data = hash от 3 parents (это подписывается вместе с essence).

**Проверка:**
- Подпись валидируется.

**Если падает:**
- Проверить сериализацию и порядок полей.

---

## Пункт 7 — Gossip/Propagation
**Тест (должен падать):**
- Узел принимает tx с 2 refs.

**Реализация:**
- Reject tx с <3 refs на ingress.

**Проверка:**
- Принимаются только 3 refs.

**Если падает:**
- Проверить ingress vs consensus слой.

---

## Пункт 8 — End-to-End интеграция
**Тест (должен падать):**
- Tx не подтверждается после 3 approvals.

**Реализация:**
- Связать submit → approvals → confirm.

**Проверка:**
- E2E: 3 approvals → confirmed.

**Если падает:**
- Проверить ApprovalIndex и confirmed status.

---

## Пункт 9 — Метрики/наблюдаемость
**Тест (должен падать):**
- Метрики approvals/latency отсутствуют.

**Реализация:**
- Добавить метрики и алерты.

**Проверка:**
- Метрики видны.

**Если падает:**
- Проверить регистрацию метрик.

---

## Пункт 10 — Migration
**Тест (должен падать):**
- Legacy tx с 2 refs всё ещё принимается.

**Реализация:**
- Coordinated upgrade: правило 3+3 enforced.

**Проверка:**
- Сеть принимает только 3+3.

**Если падает:**
- Проверить gating/version.

---

## Обязательные тестовые сценарии (реальные)
1) 2 refs → reject  
2) 3 refs → accept  
3) duplicate refs → reject  
4) approvals увеличиваются у родителей  
5) confirmed на 3-м approval  
6) ingress reject legacy 2-ref tx

---

## Допущения
- Реализация идёт через существующий consensus слой (без нового DAG gRPC API).
- Если tip selection отсутствует — реализуется минимальная версия, достаточная для 3+3.
