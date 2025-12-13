# YESRouter vBNG - Industry-Grade Fixes

## Root Cause Analysis

### 1. PPPoE/LCP/IPCP State Machine Issues

**Problem:** `ppp_auth_start()` is called multiple times in `ppp_lcp.c`:
- Line 131: After sending Configure-Ack
- Line 275-278: After receiving Configure-Request (called twice!)
- Line 290: After receiving Configure-Ack

**Root Cause:** RFC 1661 state machine not properly implemented. The LCP FSM should only trigger authentication ONCE when entering OPENED state.

**Fix:** Consolidate auth start into a single state transition function.

---

### 2. Missing Timers and Retransmission

**Problem:** LCP/IPCP negotiations can stall because:
- No automatic retransmission of Configure-Request
- No timeout handling for stuck negotiations
- `last_conf_req_ts` is set but never checked

**Root Cause:** Timer wheel not integrated with PPP FSM.

**Fix:** Implement proper RFC 1661 restart timer with exponential backoff.

---

### 3. Race Conditions in Session Management

**Problem:** PPPoE session state can be modified concurrently:
- RX thread processes packets
- Management thread checks timeouts
- RADIUS callbacks modify session state

**Root Cause:** No synchronization primitives protecting session state transitions.

**Fix:** Add per-session spinlocks or use lock-free state machine.

---

### 4. NAT Session Aging Issues

**Problem:** NAT sessions occasionally dropped because:
- Timeout check runs on separate thread without proper synchronization
- Session deletion can race with packet processing

**Fix:** Use RCU-like pattern for session deletion.

---

### 5. Worker Thread Initialization

**Problem:** Worker threads sometimes fail to initialize because:
- DPDK lcore assignment not verified
- Missing error handling in thread creation

**Fix:** Add proper initialization verification and retry logic.

---

### 6. Logging Issues

**Problem:**
- fprintf(stderr) is not thread-safe
- No rate limiting for high-frequency logs
- Debug statements mixed with production code

**Fix:** Implement industry-grade logging with:
- Thread-safe buffered output
- Rate limiting
- Log levels properly enforced
- journald integration

---

### 7. Systemd Integration

**Problem:** Using `nohup` is unreliable:
- No proper signal handling
- No automatic restart
- No resource limits
- Stale DPDK files not cleaned

**Fix:** Proper systemd service with:
- Pre-start cleanup script
- Resource limits (MEMLOCK, NOFILE)
- Restart policy
- journald logging

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         YESRouter vBNG Architecture                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      CONTROL PLANE                               │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │    │
│  │  │   CLI   │  │ RADIUS  │  │  Timer  │  │   HA    │            │    │
│  │  │ Socket  │  │ Client  │  │  Wheel  │  │  Sync   │            │    │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘            │    │
│  │       │            │            │            │                  │    │
│  │       └────────────┴─────┬──────┴────────────┘                  │    │
│  │                          │                                       │    │
│  │                   ┌──────▼──────┐                               │    │
│  │                   │   Session   │                               │    │
│  │                   │   Manager   │                               │    │
│  │                   └──────┬──────┘                               │    │
│  └──────────────────────────┼───────────────────────────────────────┘    │
│                             │                                            │
│  ┌──────────────────────────▼───────────────────────────────────────┐   │
│  │                       DATA PLANE                                  │   │
│  │                                                                   │   │
│  │   ┌─────────────────────────────────────────────────────────┐   │   │
│  │   │                    DPDK RX/TX                            │   │   │
│  │   │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  │   │   │
│  │   │  │ Q0  │  │ Q1  │  │ Q2  │  │ Q3  │  │ Q4  │  │ Q5  │  │   │   │
│  │   │  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  │   │   │
│  │   └─────┼────────┼────────┼────────┼────────┼────────┼──────┘   │   │
│  │         │        │        │        │        │        │          │   │
│  │   ┌─────▼────────▼────────▼────────▼────────▼────────▼──────┐   │   │
│  │   │              Worker Cores (1 per RX Queue)               │   │   │
│  │   │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐        │   │   │
│  │   │  │Worker 0│  │Worker 1│  │Worker 2│  │Worker N│        │   │   │
│  │   │  └───┬────┘  └───┬────┘  └───┬────┘  └───┬────┘        │   │   │
│  │   └──────┼───────────┼───────────┼───────────┼──────────────┘   │   │
│  │          │           │           │           │                  │   │
│  │   ┌──────▼───────────▼───────────▼───────────▼──────────────┐   │   │
│  │   │                  Packet Pipeline                         │   │   │
│  │   │                                                          │   │   │
│  │   │  ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐  │   │   │
│  │   │  │Parse │──▶│PPPoE │──▶│ NAT  │──▶│ QoS  │──▶│Route │  │   │   │
│  │   │  │      │   │LCP/  │   │ 44   │   │HQoS  │   │ FIB  │  │   │   │
│  │   │  │      │   │IPCP  │   │      │   │      │   │      │  │   │   │
│  │   │  └──────┘   └──────┘   └──────┘   └──────┘   └──────┘  │   │   │
│  │   └──────────────────────────────────────────────────────────┘   │   │
│  └───────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

PPPoE State Machine (RFC 2516 + RFC 1661):
==========================================

  PADI ──▶ [PADO] ──▶ PADR ──▶ [PADS] ──▶ SESSION
                                              │
                                              ▼
                                     ┌────────────────┐
                                     │  LCP Initial   │
                                     └───────┬────────┘
                                             │ This-Layer-Up
                                             ▼
                                     ┌────────────────┐
                                     │  LCP Starting  │◀──┐
                                     └───────┬────────┘   │
                                             │ Send CR    │ Timeout
                                             ▼            │
                                     ┌────────────────┐   │
                                     │  LCP Req-Sent  │───┘
                                     └───────┬────────┘
                                             │ RCA
                                             ▼
                                     ┌────────────────┐
                                     │  LCP Ack-Rcvd  │
                                     └───────┬────────┘
                                             │ RCR+ (send CA)
                                             ▼
                                     ┌────────────────┐
                                     │  LCP Opened    │
                                     └───────┬────────┘
                                             │ Auth Required
                                             ▼
                                     ┌────────────────┐
                                     │  CHAP/PAP      │
                                     │  Authentication│
                                     └───────┬────────┘
                                             │ Auth Success
                                             ▼
                                     ┌────────────────┐
                                     │  IPCP Initial  │
                                     └───────┬────────┘
                                             │
                                             ▼
                                     ┌────────────────┐
                                     │  IPCP Opened   │
                                     └───────┬────────┘
                                             │
                                             ▼
                                     ┌────────────────┐
                                     │  SESSION ACTIVE│
                                     │  (Data Plane)  │
                                     └────────────────┘

NAT44 Pipeline:
===============

  Ingress ──▶ Session Lookup ──▶ Translation ──▶ Egress
                  │                    │
                  │ Miss               │
                  ▼                    │
             Create Session           │
                  │                   │
                  ▼                   │
             Port Allocation          │
                  │                   │
                  └───────────────────┘

```

## Performance Tuning Recommendations

### DPDK Settings
```
# /etc/yesrouter/dpdk.conf
socket_mem=4096
num_mbufs=262144
rx_ring_size=2048
tx_ring_size=2048
burst_size=64
```

### Hugepage Configuration
```bash
# /etc/sysctl.d/99-hugepages.conf
vm.nr_hugepages=4096
vm.hugetlb_shm_group=0
```

### CPU Isolation
```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="isolcpus=1-7 nohz_full=1-7 rcu_nocbs=1-7"
```
