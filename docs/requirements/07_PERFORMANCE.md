# LockBox Requirements - Performance Requirements

> **Note:** This section not necessary for development or our first version in production.

## 9. Performance Requirements

### 9.1 Transaction Throughput

#### 9.1.1 Initial Target

| Metric | Target |
|--------|--------|
| Sustained TPS | 100 TPS for 10 minutes |
| Node Participation | 50% |
| Key Size | 64-character, Standard tier |
| Success Rate | 90% without retries |
| Node Count | ≥20 nodes |

#### 9.1.2 Scaling Target

- Linear scaling to 1000+ TPS with additional nodes
- ~10 TPS per node at 100 nodes

---

### 9.2 Latency Requirements

#### 9.2.1 Storage Operations

- <1s for 95% of transactions

#### 9.2.2 Retrieval Operations

| Operation | Target Latency | Percentile |
|-----------|---------------|------------|
| Full Operation | <500ms | 90% |
| Individual Shard | <100ms | 95% |
| Full Bundle (96 shards) | <300ms | 90% |

---

### 9.3 Node Requirements

#### 9.3.1 Minimum Specifications

| Resource | Requirement |
|----------|-------------|
| CPU | 1 GHz dual-core (e.g., ARM Cortex-A53) |
| RAM | 2 GB |
| Storage | 20 GB SSD |
| Network | 10 Mbps, <50ms latency to peers |
| OS | Linux (e.g., Ubuntu 22.04) or Docker |

#### 9.3.2 High-Performance Specifications (1000+ TPS)

| Resource | Requirement |
|----------|-------------|
| CPU | 4-core |
| RAM | 8 GB |
| Storage | 100 GB SSD |
| Network | 100 Mbps |

---

### 9.4 Stress Test Scenarios

#### 9.4.1 Node Failure

| Metric | Target |
|--------|--------|
| Failure Scope | 50% node failure (10/20 nodes) |
| Minimum TPS | ≥50 TPS |
| Shard Redistribution | <60s |
| Key Retrieval Success | 100% |

#### 9.4.2 High Load

| Metric | Target |
|--------|--------|
| TPS | 500 TPS |
| Key Size | 256-character, Elite tier |
| Latency | <2s (90%) |
| Shard Retrieval | <500ms (85%) |
| Failure Rate | ≤5% |

#### 9.4.3 Network Partitioning

| Metric | Target |
|--------|--------|
| Partition | Split 20 nodes into 10/10 for 2 minutes |
| Per-Segment TPS | ≥40 TPS |
| Resume Time | <30s after partition heals |

#### 9.4.4 Malicious Node Attack

| Metric | Target |
|--------|--------|
| Compromised Nodes | 3/20 nodes |
| Blacklist Time | <10s |
| Minimum TPS | ≥80 TPS |
| Retrieval Failure | ≤1% |

#### 9.4.5 Resource Saturation

| Metric | Target |
|--------|--------|
| Saturation | 1 node at >90% CPU/memory |
| Shard Migration | <60s |
| Data Loss | None |
| Latency Increase | <200ms |
