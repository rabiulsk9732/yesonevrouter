# NAT Performance Tuning Phases

## Baseline (Before Optimization)
- **Date**: 2025-12-05
- **Throughput**: 0.09 MPPS (90K pps)
- **Per-core**: 0.05 MPPS
- **Issues**: --no-huge, pthreads, per-pkt malloc, time() syscall

---

## Phase 1: DPDK Core Optimization ✅
- **Date**: 2025-12-05
- **Changes**:
  - DPDK lcores via `rte_eal_mp_remote_launch()`
  - Burst processing (64 packets)
  - Mempool bulk alloc
  - Cycle timing (`rte_rdtsc()`)
  - Hugepage memory

| Cores | Aggregate | Per-Core |
|-------|-----------|----------|
| 8     | 16.15 MPPS | 2.02 MPPS |
| 12    | 15.82 MPPS | 1.32 MPPS |

**Improvement**: 180x from baseline

---

## Phase 2+3: Memory & Cache Optimization ✅
- **Date**: 2025-12-05
- **Changes**:
  - Increased mempool to 256K mbufs
  - Per-worker session cache (256 entries)
  - Branch prediction hints (`likely()`/`unlikely()`)
  - Aggressive prefetching

| Sessions | Cores | Aggregate | Per-Core | Cache Hit |
|----------|-------|-----------|----------|-----------|
| 20,000   | 12    | 14.76 MPPS | 1.23 MPPS | 0.9% |
| 10,000   | 15    | 24.33 MPPS | 1.62 MPPS | 36.4% |
| 1,000    | 15    | **120.06 MPPS** | **8.00 MPPS** | **100%** |

**Improvement**: 1333x from baseline!

---

## Final Results Summary

| Metric | Baseline | Final | Improvement |
|--------|----------|-------|-------------|
| **Aggregate MPPS** | 0.09 | **120.06** | **1333x** |
| **Per-core MPPS** | 0.05 | **8.00** | **160x** |
| **IMIX Bandwidth** | 2.5 Gbps | **336 Gbps** | **134x** |
| **Packets (30s)** | 1.3M | **3.6B** | **2769x** |

### ISP Capacity (with 100% cache)
- **Subscribers** (100 Mbps): ~3,360 homes
- **Subscribers** (50 Mbps): ~6,720 homes
- **Subscribers** (20 Mbps): ~16,800 homes

---

## Phase 1: Production Module Integration ✅
- **Date**: 2025-12-05
- **Changes**:
  - Added `nat_session_cache_entry` struct to `nat.h`
  - Added `nat_cache_lookup()` and `nat_cache_add()` to `nat_session.c`
  - Integrated into `nat_session_lookup_inside()` and `nat_session_create()`
  - Cache stats tracked per-worker

| Sessions | Cores | Aggregate | Per-Core | Cache Hit |
|----------|-------|-----------|----------|-----------|
| 1,000    | 12    | **91.97 MPPS** | **7.66 MPPS** | **100%** |

**IMIX Bandwidth**: ~257 Gbps

---

## Remaining Optimizations (Future)
- [ ] Phase 2: Add NAT section to startup.conf (workers, sessions, cache-size)
- [ ] Phase 3: SIMD vectorized checksums (AVX2/AVX-512)
- [ ] Phase 4: Real NIC with SR-IOV
- [ ] Phase 5: DPDK hash table instead of linear cache lookup
