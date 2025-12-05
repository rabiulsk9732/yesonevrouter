# NAT Statistics Diagnosis Issue

## Problem

**Statistics show:**
- `In2Out hits: 0`
- `In2Out misses: 0`
- `ICMP echo requests: 0`
- `ICMP echo replies: 0`

**But ping is working 99-100%!**

This suggests:
1. SNAT is being called but counters aren't being incremented
2. OR SNAT is returning early before reaching counter code
3. OR statistics are being read from stale/wrong instance

## Root Cause Analysis

### Hypothesis 1: Early Return
SNAT has early return at line 87-89:
```c
if (!m || !g_nat_config.enabled) {
    return -1;
}
```

If this returns early, no counters are incremented.

### Hypothesis 2: Statistics Not Updated
The counters use `__atomic_fetch_add` but might not be visible due to:
- Memory ordering issues
- Statistics read from different memory location
- Race conditions

### Hypothesis 3: Different Code Path
Maybe packets are taking a different path that doesn't go through SNAT?

## Fix Applied

Added diagnostic counters:
- `snat_function_calls` - Tracks every SNAT invocation
- `snat_early_returns` - Tracks early returns

This will show:
- If SNAT is being called at all
- How many times it returns early
- Difference = actual SNAT processing attempts

## Next Steps

1. Rebuild with diagnostic counters
2. Run test again
3. Check new statistics:
   - `SNAT function calls` should be > 0 if SNAT is invoked
   - `SNAT early returns` shows why it might be failing
   - `SNAT function calls - SNAT early returns` = actual processing attempts

## Expected Results

If SNAT is being called:
- `SNAT function calls` > 0
- `SNAT early returns` < `SNAT function calls`
- Difference should match `In2Out hits + In2Out misses`

If SNAT is NOT being called:
- `SNAT function calls` = 0
- Problem is in forwarding path, not SNAT itself
