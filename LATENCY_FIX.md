# Latency Optimization Fix

## Problem
NAT is working but with extremely high latency (1-2 seconds, 500-2500ms). High packet loss initially (93%), then working but still slow.

## Root Causes

### 1. **Single-Packet RX Burst (MAJOR)**
- `rte_eth_rx_burst()` was called with burst size of 1
- DPDK is designed for burst processing (32-64 packets at a time)
- Processing 1 packet at a time adds massive per-packet overhead

### 2. **Excessive Sleep in RX Loop (MAJOR)**
- `usleep(100)` (100 microseconds) called when no packets received
- Accumulates quickly during low traffic periods
- Delays response to incoming packets

### 3. **Excessive Logging in Fast Path**
- `YLOG_INFO` for every forwarded packet (line 489)
- `YLOG_INFO` for every ARP packet (line 64)
- `YLOG_INFO` for every ICMP echo request (line 108)
- Logging is extremely expensive and blocks packet processing

### 4. **ARP Resolution Delays**
- When ARP entry not found, packet is dropped
- ARP resolution is asynchronous but handled synchronously
- Multiple packets dropped before ARP resolves
- Causes initial packet loss and delays

### 5. **No Packet Queuing for ARP**
- Packets are dropped when ARP not available
- Should queue packets waiting for ARP (VPP does this)
- Current implementation: drop and retry on next packet

## Fixes Applied

### 1. Removed time() Syscalls from Fast Path (NEW - 2025-12-05)
- Removed `time(NULL)` from `pkt_alloc()` - was called for every packet allocation
- Removed duplicate timestamp updates in `interface_send()`/`interface_recv()` (physical.c already tracked stats)
- Removed timestamp updates from physical.c send/recv functions
- File: `src/core/packet.c`, `src/interfaces/interface.c`, `src/interfaces/physical.c`

**Impact:** Eliminated 4-6 syscalls per packet, massive latency reduction

### 2. In-Place ICMP Echo Reply (NEW - 2025-12-05)
- Modified `process_icmp_echo()` to modify packet in-place instead of allocating new buffer
- Uses incremental checksum update instead of full recalculation
- Eliminates pkt_alloc()/pkt_free() overhead for every ping reply
- File: `src/forwarding/packet_rx.c`

**Impact:** Zero allocation overhead for ping replies

### 3. Relaxed Atomic Operations (NEW - 2025-12-05)
- Changed `__ATOMIC_SEQ_CST` to `__ATOMIC_RELAXED` for packet statistics
- Sequential consistency is overkill for simple counters
- File: `src/core/packet.c`

**Impact:** Reduced memory barrier overhead

### 4. DPDK Burst Mode RX (2025-12-04)
- Changed `physical_recv()` to use 32-packet burst buffer
- Packets are received in bursts and returned one at a time
- Dramatically reduces per-packet DPDK overhead
- File: `src/interfaces/physical.c`

### 2. Adaptive Sleep in RX Thread (NEW - 2025-12-04)
- Reduced sleep from 100µs to 10µs
- Added adaptive sleep: only sleeps after 1000+ idle loops
- Tight poll loop when traffic is expected
- Process up to 64 packets per interface before moving to next
- File: `src/forwarding/packet_rx.c`

### 3. Reduced Logging Verbosity
- Changed `YLOG_INFO` to removed/`YLOG_DEBUG` for:
  - Packet forwarding (removed completely - too verbose)
  - ARP packet processing (removed)
  - ICMP echo requests (removed)
  - TTL exceeded (changed to DEBUG)

**Impact:** Massive performance improvement - logging was blocking the fast path

### 4. ARP Handling (Current)
- Sends ARP request when entry not found
- Drops packet if ARP still not available
- Will retry on next packet

**Note:** For better performance, should implement packet queuing for ARP resolution (future improvement)

## Expected Performance After Fix

**Before:**
- High latency: 500-2500ms (even 1000+ms reported)
- High packet loss initially
- Logging overhead blocking processing
- Single-packet RX causing high overhead
- Excessive sleep delays
- 4-6 time() syscalls per packet
- New allocation for every ICMP reply

**After:**
- Expected latency: <10ms for ICMP echo (local response)
- Expected latency: 40-50ms for forwarded traffic
- Burst mode RX (32 packets at a time)
- Adaptive sleep (10µs only after extended idle)
- Multi-packet processing per poll iteration
- Zero syscalls in ICMP reply fast path
- In-place packet modification for ping replies
- Relaxed atomics for counters
- Still some initial packet loss until ARP resolves (expected)

## Remaining Issues

### ARP Resolution Delay
The current implementation drops packets when ARP is not available. For optimal performance, should implement:
- Packet queuing for ARP resolution
- Retry mechanism with backoff
- ARP entry caching optimization

This is a known limitation - VPP implements sophisticated ARP handling with packet queuing.

## Testing

After recompiling, test:
```bash
# From client
ping 8.8.8.8 -c 100
```

**Expected:**
- Lower latency (should be < 100ms for local network)
- Better packet success rate
- Faster processing

## Code Changes

### File: `src/core/packet.c` (NEW - 2025-12-05)
1. Removed `#include <time.h>`
2. Removed `time(NULL)` from `pkt_alloc()` - timestamp set to 0
3. Changed `__ATOMIC_SEQ_CST` to `__ATOMIC_RELAXED` for all packet stats

### File: `src/interfaces/interface.c` (NEW - 2025-12-05)
1. Removed duplicate statistics updates from `interface_send()` (driver handles it)
2. Removed duplicate statistics updates from `interface_recv()` (driver handles it)
3. Removed `time(NULL)` calls from fast path

### File: `src/interfaces/physical.c` (UPDATED - 2025-12-05)
1. Removed `time(NULL)` from send/recv stats updates
2. Timestamps now updated periodically, not per-packet

### File: `src/forwarding/packet_rx.c` (UPDATED - 2025-12-05)
1. `process_icmp_echo()` now modifies packet in-place
2. Uses incremental ICMP checksum update
3. No allocation/free for ping replies

### File: `src/interfaces/physical.c` (2025-12-04)
1. Added `DPDK_RX_BURST_SIZE` constant (32 packets)
2. Added burst buffer fields to `physical_priv` struct
3. Modified `physical_recv()` to use burst buffering
4. Initialize burst buffer in `physical_init()`

### File: `src/forwarding/packet_rx.c`
1. Changed RX loop to process up to 64 packets per interface
2. Reduced sleep from 100µs to 10µs
3. Added adaptive sleep (only after 1000+ idle loops)
4. Removed `YLOG_INFO` for packet forwarding
5. Removed `YLOG_INFO` for ARP processing
6. Removed `YLOG_INFO` for ICMP echo requests
7. Changed TTL exceeded to `YLOG_DEBUG`

## Performance Tips

1. **Disable debug logging in production:**
   - Set log level to WARNING or ERROR
   - Reduces overhead even more

2. **Monitor ARP table:**
   ```bash
   yesrouterctl show arp
   ```
   - Ensure gateway and client MACs are cached
   - Reduces ARP resolution delays

3. **Check forwarding statistics:**
   ```bash
   # Look for packets_dropped_arp_failed
   # High count = ARP resolution issues
   ```

## Future Improvements

1. **Packet Queuing for ARP:**
   - Queue packets waiting for ARP resolution
   - Send when ARP entry becomes available
   - Reduces packet loss

2. **ARP Pre-population:**
   - Pre-populate ARP table for known hosts
   - Reduces initial delays

3. **Batch Processing:**
   - Process multiple packets in batch
   - Reduces per-packet overhead
