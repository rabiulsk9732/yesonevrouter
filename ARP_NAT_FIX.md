# ARP Resolution Fix for NAT

## Problem Identified

NAT is working correctly (translations are happening), but packets are being dropped because:
1. **ARP resolution fails** for the gateway (103.174.247.65)
2. When ARP lookup fails, the code was just dropping packets
3. No ARP request was being sent

## Fix Applied

Modified `src/forwarding/packet_rx.c` to:
1. **Send ARP request** when ARP lookup fails
2. Try lookup again (in case it was cached)
3. Drop packet only if ARP still fails (will retry on next packet)

## What to Check

### 1. Verify ARP Table Has Gateway Entry
```bash
yesrouterctl show arp
```

**Should show:**
```
103.174.247.65    <MAC_ADDRESS>    Gi0/1    VALID
```

**If missing:**
- The fix will send ARP request automatically
- Wait a moment and check again
- Or manually trigger: `ping 103.174.247.65` from router

### 2. Check ARP Statistics
```bash
yesrouterctl show arp
```

Look for:
- ARP requests sent
- ARP replies received

### 3. Monitor Logs
```bash
journalctl -u yesrouter -f | grep -i arp
```

Look for:
- "sending ARP request" - ARP request being sent
- "ARP entry still not available" - Waiting for ARP reply
- "No ARP entry" - ARP lookup failed

### 4. Test from Client
```bash
# From client (172.16.17.2)
ping 8.8.8.8
```

**Expected behavior:**
1. First packet: ARP request sent, packet dropped
2. ARP reply received, gateway MAC cached
3. Subsequent packets: Forwarded successfully

## Manual ARP Resolution (if needed)

If ARP still doesn't resolve, you can manually trigger:

```bash
# From router, ping the gateway
ping 103.174.247.65

# Or check ARP table
yesrouterctl show arp
```

## Expected Flow After Fix

1. **Client sends packet:**
   - Source: 172.16.17.2
   - Destination: 8.8.8.8

2. **Router receives:**
   - NAT translates: 172.16.17.2 → 103.174.247.67
   - Route lookup: Next-hop = 103.174.247.65 (gateway)

3. **ARP resolution:**
   - ARP lookup for 103.174.247.65
   - If not found: Send ARP request
   - Wait for ARP reply (or drop first packet)

4. **Forward packet:**
   - Use gateway MAC from ARP table
   - Send packet to gateway

5. **Return traffic:**
   - DNAT translates back to 172.16.17.2
   - Forward to client

## Troubleshooting

### If packets still don't work:

1. **Check ARP table:**
   ```bash
   yesrouterctl show arp
   ```
   Gateway (103.174.247.65) should be present

2. **Check if ARP requests are being sent:**
   ```bash
   journalctl -u yesrouter | grep -i "arp request"
   ```

3. **Check forwarding statistics:**
   ```bash
   # Look for packets_dropped_arp_failed counter
   ```

4. **Verify gateway is reachable:**
   ```bash
   # From router
   ping 103.174.247.65
   ```

5. **Check interface configuration:**
   ```bash
   yesrouterctl show interfaces
   ```
   WAN interface (Gi0/1) should have IP 103.174.247.67

## Code Changes

**File:** `src/forwarding/packet_rx.c`

**Before:**
```c
if (arp_lookup(next_hop_ip, next_hop_mac) != 0) {
    YLOG_WARNING("No ARP entry...");
    return -1;  // Just drop
}
```

**After:**
```c
if (arp_lookup(next_hop_ip, next_hop_mac) != 0) {
    // Send ARP request
    arp_send_request(next_hop_ip, src_ip, egress_iface->mac_addr, egress_iface->ifindex);
    // Try again (might be cached)
    if (arp_lookup(next_hop_ip, next_hop_mac) != 0) {
        // Drop, will retry on next packet
        return -1;
    }
}
```
