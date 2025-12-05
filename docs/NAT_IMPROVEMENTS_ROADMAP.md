# NAT Improvements Roadmap

## Current Status ✅
- NAT working at 99-100% success rate
- Basic SNAT/DNAT functional
- ICMP echo request/reply working
- Session management working

## Priority 1: Critical Performance (High Impact)

### 1.1 Per-Worker Session Tables (Lockless)
**Problem:** Multiple RX threads contending for same hash bucket locks
**Impact:** Reduces lock contention, improves throughput by 10-50x
**Effort:** Medium
**VPP Pattern:** Each worker has its own session table, sessions assigned by flow hash

**Implementation:**
- Use existing `g_nat_workers[]` structure (already defined in nat_session.c)
- Assign sessions to workers based on flow hash
- Each worker only accesses its own table (lockless)
- Cross-worker access only needed for session creation/deletion

### 1.2 Packet Queuing for ARP Resolution
**Problem:** Packets dropped when ARP entry not found, causing retransmissions
**Impact:** Eliminates initial packet loss, improves first-packet latency
**Effort:** Medium
**VPP Pattern:** Queue packets waiting for ARP, send when ARP reply arrives

**Implementation:**
- Add per-IP packet queue
- When ARP lookup fails, queue packet
- When ARP reply arrives, flush queue
- Timeout queue after 1-2 seconds

### 1.3 Optimize Hash Table Lookups
**Problem:** Hash collisions causing linear search through chains
**Impact:** Reduces lookup latency, especially under load
**Effort:** Low
**VPP Pattern:** Better hash function, larger table, or cuckoo hashing

**Implementation:**
- Increase table size (currently 64M, could use power-of-2 sizing)
- Use better hash function (CRC32, xxhash)
- Consider cuckoo hashing for lockless operation

## Priority 2: Statistics & Observability (Medium Impact)

### 2.1 Fix Statistics Tracking
**Problem:** Counters showing 0 even though NAT is working
**Impact:** Cannot diagnose issues, no visibility
**Effort:** Low
**Status:** In progress (diagnostic counters added)

**Implementation:**
- Fix counter updates (ensure atomic operations)
- Add per-protocol counters (TCP/UDP/ICMP separately)
- Add per-interface counters
- Add rate counters (packets/sec, bytes/sec)

### 2.2 Session Dump with Details
**Problem:** Can't see session details (timeouts, packet counts, etc.)
**Impact:** Better debugging and monitoring
**Effort:** Low

**Implementation:**
- Enhanced `show nat translations` with:
  - Session age
  - Packet/byte counts
  - Last activity timestamp
  - Timeout remaining
  - Flags (EIM, hairpin, etc.)

### 2.3 Performance Metrics
**Problem:** No visibility into NAT performance bottlenecks
**Impact:** Identify optimization opportunities
**Effort:** Medium

**Implementation:**
- Lookup latency (min/avg/max)
- Lock contention counters
- Hash collision statistics
- Memory pool usage
- Session creation/deletion rates

## Priority 3: Reliability & Edge Cases (Medium Impact)

### 3.1 Session Timeout Improvements
**Problem:** Sessions timing out during active flows
**Impact:** Reduces mid-flow failures
**Effort:** Low

**Implementation:**
- Extend timeout on packet activity (already done in lookup)
- Different timeouts for different states (TCP ESTABLISHED vs SYN_SENT)
- Graceful timeout (mark for deletion, allow brief grace period)

### 3.2 Better Error Handling
**Problem:** Silent failures, unclear error messages
**Impact:** Easier debugging
**Effort:** Low

**Implementation:**
- Detailed error codes
- Error statistics per error type
- Logging with context (packet details, session details)

### 3.3 ICMP Error Message Handling
**Problem:** ICMP errors (Destination Unreachable, etc.) not properly translated
**Impact:** Better error reporting to clients
**Effort:** Medium

**Implementation:**
- Use existing `alg_icmp_process_error()` function
- Call it for ICMP error messages
- Translate embedded IP headers in error messages

## Priority 4: VPP Parity Features (Low-Medium Impact)

### 4.1 FIB Index in Session Key
**Problem:** Multi-VRF support requires FIB index in key
**Impact:** Enables multi-VRF NAT
**Effort:** Medium

**Implementation:**
- Add `fib_index` to session key
- Include in hash function
- Get FIB index from interface/route

### 4.2 Hairpinning Support
**Problem:** Cannot NAT traffic between two private networks
**Impact:** Enables internal-to-internal NAT
**Effort:** Medium

**Implementation:**
- Detect hairpin condition (src and dst both private, same interface)
- Apply both SNAT and DNAT
- Use existing `nat_hairpin.c` code

### 4.3 Deterministic NAT
**Problem:** Port allocation is random, not deterministic
**Impact:** Enables predictable NAT for testing/debugging
**Effort:** High

**Implementation:**
- Port block allocation per subscriber
- Deterministic port assignment algorithm
- Use existing port block infrastructure

## Priority 5: Advanced Features (Low Priority)

### 5.1 NAT64/NAT46 Support
**Problem:** No IPv6 support
**Impact:** Enables IPv6-to-IPv4 translation
**Effort:** High

### 5.2 Port Forwarding (Static NAT)
**Problem:** No static port mapping
**Impact:** Enables server hosting behind NAT
**Effort:** Medium

### 5.3 NAT Session Logging (IPFIX/NetFlow)
**Problem:** No session logging for accounting/audit
**Impact:** Compliance and billing
**Effort:** Medium

## Recommended Next Steps

### Immediate (This Week):
1. ✅ Fix statistics tracking (in progress)
2. **Per-worker session tables** - Biggest performance win
3. **Packet queuing for ARP** - Eliminates initial packet loss

### Short Term (Next 2 Weeks):
4. Enhanced session dump
5. Performance metrics
6. Better error handling

### Medium Term (Next Month):
7. FIB index support
8. Hairpinning
9. ICMP error handling

## Quick Wins (Low Effort, High Impact)

1. **Reduce verbose logging** - Already done for some paths, can do more
2. **Increase hash table size** - Simple config change
3. **Add session age to dump** - Simple addition
4. **Better hash function** - Replace FNV-1a with CRC32 or xxhash

## Performance Targets

**Current:**
- 99-100% success rate ✅
- ~1.3ms latency ✅
- 1% packet loss (acceptable)

**Target:**
- 99.9%+ success rate
- <1ms latency
- <0.1% packet loss
- 10M+ packets/sec throughput
