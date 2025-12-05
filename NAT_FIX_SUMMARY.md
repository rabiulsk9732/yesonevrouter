# NAT Fix Summary

## Problem
NAT is not working for client traffic (172.16.17.2). Default route exists, but NAT translation is not happening.

## Root Causes Found

### 1. **Weak NAT Detection Logic**
The original code only checked: `if (ingress_iface->ifindex != 1)`
- This assumes interface 1 is always WAN
- If interfaces are created in different order, NAT won't apply
- Doesn't check if source IP is actually private

### 2. **Silent NAT Failures**
When NAT translation failed, the code just logged a warning and continued
- Private IPs without NAT will fail anyway
- No clear indication why NAT failed

### 3. **No Pool Check in Logs**
When NAT failed, logs didn't show if pools were configured

## Fixes Applied

### 1. **Improved NAT Detection**
Now checks:
- If ingress and egress interfaces are different (more reliable)
- OR if source IP is in private range (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- This works regardless of interface index order

### 2. **Better Error Handling**
- If NAT fails for private IP, packet is dropped (can't work without NAT)
- Detailed error logs showing: source IP, ingress/egress interface indexes, number of pools
- Warning if private IP needs NAT but NAT is disabled

### 3. **Enhanced Logging**
- Debug logs when NAT is successfully applied
- Warning logs with full context when NAT fails
- Shows pool count in error messages

## Code Changes

**File:** `src/forwarding/packet_rx.c`

**Before:**
```c
if (ingress_iface->ifindex != 1) {
    int nat_result = nat_translate_snat(pkt, egress_iface);
    if (nat_result < 0) {
        YLOG_WARNING("NAT SNAT failed for packet");
        /* Continue without NAT */
    }
}
```

**After:**
```c
uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
bool is_private_ip = ((src_ip & 0xFF000000) == 0x0A000000) ||      /* 10.0.0.0/8 */
                     ((src_ip & 0xFFF00000) == 0xAC100000) ||      /* 172.16.0.0/12 */
                     ((src_ip & 0xFFFF0000) == 0xC0A80000);        /* 192.168.0.0/16 */

if (ingress_iface->ifindex != egress_iface->ifindex || is_private_ip) {
    int nat_result = nat_translate_snat(pkt, egress_iface);
    if (nat_result < 0) {
        YLOG_WARNING("NAT SNAT failed: src=%u.%u.%u.%u ingress=%u egress=%u pools=%d",
                     ...);
        if (is_private_ip) {
            return -1; /* Drop - can't work without NAT */
        }
    }
}
```

## What to Check Now

1. **Verify NAT is enabled:**
   ```bash
   yesrouterctl show nat config
   ```
   Should show: `Status: Enabled`

2. **Verify NAT pool exists:**
   ```bash
   yesrouterctl show nat config
   ```
   Should show at least one pool with IPs

3. **Check logs when client pings:**
   Look for:
   - "NAT SNAT applied" - NAT is working
   - "NAT SNAT failed" - Check the error details (pools count, etc.)
   - "needs NAT but NAT is disabled" - NAT not enabled or no pool

4. **Check NAT statistics:**
   ```bash
   yesrouterctl show nat statistics
   ```
   Look for error counters:
   - `no_ip_available` - No NAT pool configured
   - `no_port_available` - Port exhaustion
   - `invalid_packet` - Unsupported protocol

## Expected Behavior

**With fix:**
- Client (172.16.17.2) sends packet to 1.1.1.1
- Router detects private IP (172.16.17.2) → applies NAT
- Source IP translated to WAN IP
- Packet forwarded to WAN
- Return traffic: DNAT translates back to 172.16.17.2

**If NAT fails:**
- Clear error message with details
- Packet dropped (for private IPs)
- Logs show exactly why (no pool, disabled, etc.)

## Testing

After recompiling:
1. Generate traffic from client: `ping 1.1.1.1`
2. Check logs: `yesrouterctl show nat translations`
3. Check stats: `yesrouterctl show nat statistics`
4. Verify NAT sessions are created
