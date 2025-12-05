# VBNG NAT vs VPP NAT44-ED Parity Analysis

## Current Issues (Intermittent NAT Failures)

### Symptoms
- 12-30% packet loss during flood ping
- Intermittent 100% packet loss
- Works sometimes, fails completely other times
- Good latency when working (1.1-1.3ms) but spikes to 5000ms+
- "Destination Host Unreachable" errors

### Root Cause Analysis

## Issue #1: ICMP Identifier Handling (CRITICAL)

**VPP NAT44-ED Behavior:**
- For ICMP echo request: Uses `icmp_ident` as the "port" in the 5-tuple
- For ICMP echo reply: Uses the **same identifier** that was translated in the request
- Key: `(src_ip, icmp_ident, protocol)` for in2out, `(dst_ip, translated_icmp_ident, protocol)` for out2in

**Current VBNG Behavior:**
- ✅ Uses `icmp_ident` for in2out lookup (correct)
- ❌ **PROBLEM**: For echo replies, uses `icmp_ident` from the reply packet, which may not match the translated identifier
- ❌ **PROBLEM**: ICMP echo replies from external hosts have the translated identifier, but we're looking up with the wrong key

**Fix Required:**
- Ensure echo reply uses the translated identifier from the session
- Verify key construction matches VPP exactly

## Issue #2: Hash Key Construction

**VPP NAT44-ED Key Structure:**
```c
struct nat_key {
    uint32_t addr;      // IP address
    uint16_t port;      // Port or ICMP identifier
    uint8_t protocol;   // IP protocol
    uint32_t fib_index; // FIB index (VRF) - CRITICAL for multi-VRF
}
```

**Current VBNG Key:**
- ✅ Uses (ip, port, protocol)
- ❌ **MISSING**: `fib_index` - Not included in hash
- ⚠️ **RISK**: If multi-VRF is used, sessions could collide

**Fix Required:**
- Add fib_index to session key (if multi-VRF is used)
- For now, assume fib_index=0 (single VRF)

## Issue #3: Multi-Threaded Session Access

**Current Implementation:**
- Multiple RX threads (one per core)
- Shared session tables with RW locks
- Lock contention under high load

**VPP NAT44-ED Pattern:**
- Per-worker session tables (lockless within worker)
- Sessions assigned to workers based on flow hash
- Minimal lock contention

**Fix Required:**
- Implement per-worker session tables (already partially implemented but not used)
- Or: Use lockless hash table with RCU

## Issue #4: Session Timeout During Active Flow

**Current Behavior:**
- Sessions timeout after 60 seconds (ICMP)
- If ping flood lasts > 60s, sessions expire mid-flow
- New session created, but old packets may still be in flight

**Fix Required:**
- Extend timeout on packet activity (already done in lookup)
- But: Race condition if session expires between in2out and out2in

## Issue #5: ICMP Echo Reply Key Mismatch

**Critical Bug:**
When external host sends ICMP echo reply:
1. Packet arrives: `dst_ip = translated_public_ip, icmp_ident = translated_id`
2. DNAT lookup uses: `(translated_public_ip, translated_id, ICMP)`
3. Should find session created during in2out
4. **BUT**: If session was created with different identifier (race condition), lookup fails

**Root Cause:**
- ICMP identifier translation happens in SNAT
- But the identifier in the reply packet is the translated one
- If we look up with the wrong identifier, we miss the session

## Issue #6: Missing Statistics

**Required Counters:**
- `in2out_hits` / `in2out_misses` ✅ (exists)
- `out2in_hits` / `out2in_misses` ✅ (exists)
- `session_create` / `session_delete` ✅ (exists)
- `icmp_echo_requests` / `icmp_echo_replies` ❌ (missing)
- `icmp_identifier_mismatches` ❌ (missing)

## Testing Plan

1. **Capture with dpdk-pdump:**
   ```bash
   # On router
   dpdk-pdump -- --pdump 'port=0,queue=*,rx-dev=/tmp/rx.pcap,tx-dev=/tmp/tx.pcap'
   ```

2. **Compare session dumps:**
   ```bash
   yesrouterctl show nat translations > sessions_before.txt
   # Run ping
   yesrouterctl show nat translations > sessions_after.txt
   diff sessions_before.txt sessions_after.txt
   ```

3. **Monitor counters:**
   ```bash
   watch -n 1 'yesrouterctl show nat statistics'
   ```

## Fix Priority

1. **P0 (Critical)**: ICMP identifier handling for echo replies
2. **P1 (High)**: Add missing statistics
3. **P2 (Medium)**: Per-worker session tables
4. **P3 (Low)**: Add fib_index to key (if multi-VRF needed)
