# DevNet/TestNet Deployment Plan

**Date:** 2026-01-14
**Status:** Planning Phase
**Target:** Multi-region IOTA + LockBox deployment

---

## Executive Summary

**Что есть сейчас:**
- ✅ Private Tangle setup (`private_tangle/docker-compose.yml`)
- ✅ HORNET nodes configuration
- ✅ Dockerfile для LockBox
- ⚠️ Всё local, нет multi-region

**Что нужно:**
- 🔧 Multi-region deployment
- 🔧 Real IOTA testnet integration
- 🔧 Geographic distribution testing (1000km enforcement)
- 🔧 mTLS between nodes
- 🔧 XSD payments on ledger

---

## Phased Approach (Recommended)

### Phase 1: Local DevNet (Week 1) ⚡ START HERE

**Goal:** Быстрая проверка что всё работает

**We already have:**
- ✅ `private_tangle/docker-compose.yml` - IOTA Private Tangle
- ✅ `Dockerfile` - LockBox node image
- ✅ HORNET nodes configured

**What to add:**
- 🔧 Multi-node LockBox docker-compose
- 🔧 mTLS certificates generation script
- 🔧 Node discovery mechanism
- 🔧 Basic monitoring (Prometheus/Grafana)

**Timeline:** 1-2 days
**Cost:** $0 (local Docker)

**Setup Steps:**

```bash
# 1. Start Private Tangle (ALREADY EXISTS)
cd private_tangle
docker-compose --profile snapshots up create-snapshots
docker-compose --profile bootstrap up bootstrap-network
docker-compose up -d

# 2. Generate mTLS certs
./scripts/gen-devnet-certs.sh

# 3. Start LockBox nodes
docker-compose -f docker-compose-lockbox-devnet.yml up -d

# 4. Verify
docker ps | grep -E "hornet|lockbox"
grpcurl -plaintext localhost:50051 lockbox.LockBoxService/GetHealth
```

**Success Criteria:**
- ✅ 2+ HORNET nodes running
- ✅ 3+ LockBox nodes connected
- ✅ Lock/Unlock flow works locally
- ✅ Shards distributed across nodes
- ✅ mTLS between nodes working

---

### Phase 2: Cloud DevNet (Week 2) 🌐

**Goal:** Real network conditions, single region

**Infrastructure:** AWS us-east-1 (or GCP us-central1)

**Components:**
```
Region: us-east-1
├── 2x HORNET nodes (t3.small)
├── 3x LockBox nodes (t3.medium)
├── 1x Monitoring stack (t3.micro)
└── VPC + Security Groups
```

**Deployment Method:** Terraform

**What to build:**
- 🔧 `terraform/devnet/` - Infrastructure as Code
- 🔧 Auto-scaling groups (optional)
- 🔧 Load balancer for API
- 🔧 Monitoring (Prometheus/Grafana)

**Timeline:** 3-5 days
**Cost:** ~$125/month

**Deploy:**
```bash
cd terraform/devnet
terraform init
terraform apply

# Get node IPs
terraform output lockbox_ips
terraform output hornet_ips

# Test
grpcurl -plaintext <node-ip>:50051 \
  lockbox.LockBoxService/LockAsset
```

**Success Criteria:**
- ✅ All nodes in cloud
- ✅ Real network latency tested
- ✅ Load balancer distributing traffic
- ✅ Monitoring dashboard working
- ✅ Can test from external clients

---

### Phase 3: Real TestNet (Week 3-4) 🌍 PRODUCTION-LIKE

**Goal:** Multi-region deployment для полного тестирования

**Infrastructure:** 3 AWS regions

**Regions:**
```
Region 1: AWS us-east-1 (Virginia, USA)
  Coordinates: 37.43° N, -78.66° W
  └── 1x LockBox + 1x HORNET

Region 2: AWS eu-west-1 (Ireland)
  Coordinates: 53.41° N, -8.24° W
  Distance from R1: ~5,200 km ✅
  └── 1x LockBox + 1x HORNET

Region 3: AWS ap-southeast-1 (Singapore)
  Coordinates: 1.35° N, 103.82° E
  Distance from R1: ~15,300 km ✅
  Distance from R2: ~10,800 km ✅
  └── 1x LockBox + 1x HORNET
```

**Geographic Verification:**
- ✅ All pairs >1000km (meets requirements)
- ✅ Tests Elite tier (5 nodes distributed)
- ✅ Tests network latency cross-region

**Additional Components:**
- VPN peering between regions
- Multi-region load balancer
- Distributed monitoring (Prometheus federation)
- Jaeger distributed tracing

**Timeline:** 1-2 weeks
**Cost:** ~$240/month

**Deploy:**
```bash
cd terraform/testnet
terraform init
terraform apply

# Verify geographic distribution
curl https://testnet.lockbox.io/api/health/geo-check

# Test Elite tier (5 nodes across regions)
grpcurl -plaintext testnet.lockbox.io:443 \
  lockbox.LockBoxService/LockAsset \
  -d '{"tier":"elite", "owner_address":"iota1..."}'
```

**Success Criteria:**
- ✅ 3 regions >1000km apart
- ✅ Geographic distance enforcement working
- ✅ Elite tier using 5+ nodes correctly
- ✅ Cross-region latency <2s
- ✅ Failover tested (1 region down, system works)
- ✅ XSD payments working on testnet
- ✅ Full monitoring & alerting

---

## Cost Comparison

| Phase | Setup Time | Monthly Cost | Use Case |
|-------|-----------|--------------|----------|
| **Phase 1: Local DevNet** | 1-2 days | $0 | Development, CI/CD |
| **Phase 2: Cloud DevNet** | 3-5 days | ~$125 | Integration testing, mTLS |
| **Phase 3: TestNet** | 1-2 weeks | ~$240 | Pre-production, client demos |

---

## What We Have vs What We Need

### Already Exists ✅

```
lockbox/
├── private_tangle/
│   ├── docker-compose.yml          ✅ HORNET Private Tangle
│   └── config_private_tangle.json  ✅ IOTA config
├── hornet-nest/
│   ├── docker-compose.yml          ✅ Multi-node setup
│   └── Dockerfile                  ✅ HORNET image
├── Dockerfile                      ✅ LockBox node image
└── integration-tests/
    └── docker-compose.yml          ✅ Test infrastructure
```

### Need to Create 🔧

**For Phase 1 (Local):**
```
lockbox/
├── docker-compose-lockbox-devnet.yml  🔧 Multi-node LockBox setup
├── scripts/
│   └── gen-devnet-certs.sh           🔧 mTLS certificate generation
└── monitoring/
    ├── docker-compose-monitoring.yml  🔧 Prometheus/Grafana
    └── prometheus.yml                 🔧 Scrape config
```

**For Phase 2 (Cloud):**
```
terraform/
└── devnet/
    ├── main.tf                       🔧 AWS infrastructure
    ├── lockbox-init.sh               🔧 Node bootstrap script
    └── variables.tf                  🔧 Configuration
```

**For Phase 3 (TestNet):**
```
terraform/
└── testnet/
    ├── main.tf                       🔧 Multi-region setup
    ├── modules/
    │   └── region/                   🔧 Per-region module
    └── monitoring/
        └── prometheus.yml            🔧 Multi-region monitoring
```

---

## Critical Questions for Lance (Zoom Tomorrow)

### 1. Infrastructure Budget

**Q:** What's the budget for testnet infrastructure?

**Options:**
- Phase 1 only (Local): $0/month - good for development
- Phase 2 (Cloud Single Region): ~$125/month - good for integration testing
- Phase 3 (Multi-Region): ~$240/month - production-like testing

**Recommendation:** Start Phase 1 immediately (free), move to Phase 2 after 1 week, Phase 3 when ready for client demos.

---

### 2. Cloud Provider Preference

**Q:** AWS, GCP, or Azure?

**Comparison:**
```
AWS:
+ Best IOTA community support
+ More regions available
+ Terraform examples exist
- Slightly more expensive

GCP:
+ Cheaper for compute
+ Better Kubernetes integration
+ Good global network
- Fewer IOTA examples

Azure:
+ Good if using Microsoft stack
+ Competitive pricing
- Less IOTA community support
```

**Recommendation:** AWS (best IOTA ecosystem support)

---

### 3. Timeline Priority

**Q:** What's more important - Testnet or Metamask?

**Options:**

A) **Testnet First (Recommended)**
- Week 1: Local DevNet
- Week 2: Cloud DevNet
- Week 3-4: Multi-Region TestNet
- Week 5+: Metamask (parallel with testnet testing)

B) **Metamask First**
- Week 1-10: Metamask fork
- Meanwhile: use local DevNet
- TestNet deployment postponed

**Recommendation:** Option A - Testnet unblocks backend testing, Metamask can develop in parallel.

---

### 4. Who Manages Infrastructure?

**Q:** Do we deploy or does Lance's team?

**Options:**

A) **We deploy & manage:**
+ We control everything
+ Can iterate fast
- Requires AWS/GCP access from Lance
- We're responsible for uptime

B) **Lance's team deploys, we provide configs:**
+ They manage infrastructure
+ We focus on code
- Slower iteration
- Need good communication

**Recommendation:** Option A for DevNet/TestNet (fast iteration), Option B for Production.

---

### 5. IOTA Network Choice

**Q:** Public IOTA Testnet or Private Tangle?

**Comparison:**
```
Public IOTA Testnet:
+ Real network conditions
+ Free faucet for test tokens
+ Community support
- We don't control it
- Possible downtime

Private Tangle:
+ Full control
+ Can reset anytime
+ No external dependencies
- Need to run coordinator
- More complex setup
```

**Recommendation:**
- Phase 1-2: Private Tangle (full control)
- Phase 3: Public IOTA Testnet (real conditions)

---

### 6. Monitoring Requirements

**Q:** What monitoring/logging do we need?

**Current plan:**
- Prometheus (metrics)
- Grafana (dashboards)
- Jaeger (distributed tracing)
- Loki (logs aggregation)

**Alternative:**
- DataDog (commercial, easier)
- CloudWatch (AWS native)
- Self-hosted ELK stack

**Recommendation:** Prometheus/Grafana (open source, cost effective, good for demos)

---

## Next Steps

### Immediate (This Week):

1. **Lance Zoom (Tomorrow 10am Pacific):**
   - Get answers to 6 questions above
   - Show this deployment plan
   - Agree on Phase 1 start date

2. **Phase 1 Setup (After Zoom):**
   ```bash
   # Day 1-2: Create missing files
   - docker-compose-lockbox-devnet.yml
   - scripts/gen-devnet-certs.sh
   - monitoring/docker-compose-monitoring.yml

   # Day 3: Test locally
   - Start Private Tangle
   - Start 3 LockBox nodes
   - Run Lock/Unlock tests

   # Day 4: Document & commit
   - README for DevNet setup
   - Commit to repo
   ```

### Week 2 (If Approved):

- Create Terraform configs for Cloud DevNet
- Deploy to AWS us-east-1
- Run integration tests
- Load testing

### Week 3-4 (If Approved):

- Multi-region Terraform
- Deploy to 3 regions
- Geographic distance testing
- XSD payment testing
- Full E2E with monitoring

---

## Risk Assessment

### High Risk

**1. IOTA Network Stability**
- Private Tangle может быть unstable
- **Mitigation:** Start with Public IOTA Testnet for critical tests

**2. Multi-Region Costs**
- Cross-region transfer fees могут вырасти
- **Mitigation:** Set billing alerts, monitor daily

**3. Geographic Distance Calculation**
- Координаты DC могут быть неточные
- **Mitigation:** Verify с AWS/GCP official coordinates

### Medium Risk

**4. mTLS Certificate Management**
- Manual cert rotation risky
- **Mitigation:** Use cert-manager or automated rotation

**5. Network Latency**
- Cross-region может превысить 2s SLA
- **Mitigation:** Test early, optimize or adjust SLA

### Low Risk

**6. Docker Image Size**
- Large images = slow deploys
- **Mitigation:** Multi-stage builds, optimize layers

---

## Recommended Decision

### My Recommendation:

**Start Phase 1 this week (Local DevNet):**
- ✅ Free (no cost)
- ✅ Fast (1-2 days)
- ✅ Unblocks development
- ✅ Can run CI/CD tests

**Move to Phase 2 next week (Cloud DevNet):**
- ✅ Real network testing
- ✅ Moderate cost (~$125/month)
- ✅ Can demo to clients remotely

**Phase 3 when needed (TestNet):**
- ✅ Production-like testing
- ✅ Multi-region validation
- ✅ Higher cost but necessary before launch

**Parallel track: Metamask development**
- Can develop wallet while testnet runs
- Integrate when ready

---

## Appendix: Quick Start Commands

### Phase 1: Start Local DevNet

```bash
# 1. Clone if needed
git clone https://github.com/LockBoxIO/LockBox.git
cd LockBox

# 2. Start Private Tangle
cd private_tangle
docker-compose --profile snapshots up create-snapshots
docker-compose --profile bootstrap up bootstrap-network
docker-compose up -d

# 3. Verify HORNET
curl http://localhost:14265/health

# 4. Generate certs (TODO: create this script)
./scripts/gen-devnet-certs.sh

# 5. Start LockBox nodes (TODO: create this compose file)
docker-compose -f docker-compose-lockbox-devnet.yml up -d

# 6. Test
grpcurl -plaintext localhost:50051 \
  lockbox.LockBoxService/GetHealth
```

### Phase 2: Deploy to AWS

```bash
# 1. Configure AWS
aws configure

# 2. Deploy infrastructure (TODO: create terraform)
cd terraform/devnet
terraform init
terraform apply

# 3. Get endpoints
terraform output lockbox_lb_dns

# 4. Test
grpcurl -plaintext <lb-dns>:443 \
  lockbox.LockBoxService/GetHealth
```

---

**Document Version:** 1.0
**Created:** 2026-01-14
**Next Review:** After Lance Zoom (2026-01-15)
**Owner:** Development Team
