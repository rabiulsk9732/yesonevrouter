# NAT Fix Patch #002: Missing Statistics Counters

## Bug Summary
**Critical Bug**: `in2out_hits` counter is never incremented, making it impossible to diagnose SNAT performance.

**Symptoms:**
- `In2Out hits: 0` even when sessions exist
- `ICMP echo requests: 0` even when packets are processed
- Cannot tell if SNAT is being called or if it's failing

## Root Cause
1. **Missing `in2out_hits` increment**: When a session is found in SNAT lookup, the hit counter is never incremented
2. **Early returns**: If SNAT returns early (NAT disabled, invalid packet), statistics aren't tracked properly
3. **No visibility**: Cannot diagnose if SNAT is being called at all

## Patch

### File: `src/nat/nat_translate.c`

**Change 1: Increment in2out_hits when session found**
```c
} else {
    /* Session found - increment hit counter */
    __atomic_fetch_add(&g_nat_config.stats.in2out_hits, 1, __ATOMIC_RELAXED);
    outside_ip = session->outside_ip;
    outside_port = session->outside_port;
}
```

**Change 2: Use atomic for invalid_packet counter**
```c
default:
    /* Invalid protocol for NAT - increment counter but don't process */
    __atomic_fetch_add(&g_nat_config.stats.invalid_packet, 1, __ATOMIC_RELAXED);
    return -1;
```

## Technical Explanation

**Before:**
- Session found → Use it → No counter increment
- Cannot tell if SNAT lookups are succeeding

**After:**
- Session found → Increment `in2out_hits` → Use it
- Can now see SNAT lookup success rate

## Test Evidence

**Before Fix:**
```
In2Out hits: 0
In2Out misses: 0
ICMP echo requests: 0
```

**After Fix (expected):**
```
In2Out hits: 1000+  (sessions found)
In2Out misses: 10   (new sessions created)
ICMP echo requests: 1000+  (packets processed)
```

## Impact

This fix enables proper diagnosis:
- Can see if SNAT is being called
- Can see SNAT lookup success rate
- Can identify if sessions are being found vs created
- Critical for debugging the packet loss issue
