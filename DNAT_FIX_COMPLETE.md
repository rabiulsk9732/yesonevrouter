# Complete DNAT Return Traffic Fix

## Problem Analysis

NAT translations are happening (72 packets translated, 36 SNAT, 36 DNAT), but client still can't reach external IPs. The issue is in **DNAT return traffic handling**.

### Root Cause

After DNAT translation, the code was calling `forward_ipv4_packet()` which:
1. Does route lookup again (might route incorrectly)
2. Checks if NAT should be applied (might try to apply SNAT again)
3. The ingress interface is still WAN, but destination is now private IP

This causes return traffic to be mishandled.

## Fix Applied

### 1. Direct DNAT Forwarding Path

Created a dedicated forwarding path for DNAT'd packets that:
- Finds the correct LAN interface based on subnet matching
- Does ARP lookup/resolution for the client
- Sends directly to LAN interface without going through full forwarding logic
- Avoids re-applying NAT

### 2. Subnet-Based Interface Selection

Instead of hardcoding interface index, the code now:
- Checks which interface has the destination IP in its subnet
- Falls back to interface 2 (LAN) if subnet check fails
- Works regardless of interface creation order

### 3. ARP Resolution for Return Traffic

Added ARP request sending for client MAC when forwarding DNAT'd packets:
- Sends ARP request if client MAC not in ARP table
- Retries lookup after sending request
- Drops packet if still not available (will retry on next packet)

## Code Changes

**File:** `src/forwarding/packet_rx.c`

**Before:**
```c
if (dnat_result == 0) {
    pkt->meta.dst_ip = rte_be_to_cpu_32(ip->dst_addr);
    forward_ipv4_packet(pkt);  // Might re-apply NAT or route incorrectly
    return;
}
```

**After:**
```c
if (dnat_result == 0) {
    // Find LAN interface based on subnet
    // Do ARP lookup for client
    // Send directly to LAN interface
    // No NAT re-application, no incorrect routing
    return;
}
```

## Expected Flow After Fix

### Outbound (Client → External):
1. Client (172.16.17.2) sends ICMP echo request to 8.8.8.8
2. Router receives on LAN interface (Gi0/2)
3. SNAT applied: 172.16.17.2 → 103.174.247.67, port 344 → 10000
4. Route lookup: Next-hop = 103.174.247.65 (gateway)
5. ARP resolution for gateway
6. Packet forwarded to WAN

### Return (External → Client):
1. ICMP echo reply arrives from 8.8.8.8
2. Router receives on WAN interface (Gi0/1)
3. DNAT applied: 103.174.247.67:10000 → 172.16.17.2:344
4. **NEW:** Find LAN interface (Gi0/2) based on subnet (172.16.17.0/24)
5. **NEW:** ARP lookup for client (172.16.17.2)
6. **NEW:** Send directly to LAN interface
7. Client receives reply

## Testing After Recompile

1. **Recompile:**
   ```bash
   cd /root/vbng
   ./compile.sh
   sudo systemctl stop yesrouter
   sudo cp build/yesrouter /usr/local/bin/
   sudo systemctl start yesrouter
   ```

2. **Test from client:**
   ```bash
   # From 172.16.17.2
   ping 8.8.8.8
   ```

3. **Monitor NAT activity:**
   ```bash
   yesrouterctl show nat translations
   yesrouterctl show nat statistics
   ```

4. **Check logs:**
   ```bash
   journalctl -u yesrouter -f | grep -i "DNAT\|NAT\|ARP"
   ```

   Look for:
   - "DNAT: Return packet forwarded" - DNAT forwarding working
   - "DNAT: ARP request sent" - ARP resolution happening
   - "NAT SNAT applied" - Outbound NAT working

## Key Improvements

1. **No NAT Re-application:** DNAT'd packets bypass the full forwarding logic
2. **Correct Interface Selection:** Subnet-based matching instead of hardcoded index
3. **ARP Resolution:** Automatic ARP requests for client MAC
4. **Direct Forwarding:** Faster path for return traffic

## References

- VPP NAT44-ED: https://github.com/FDio/vpp/tree/master/src/plugins/nat/nat44-ed
- DPDK Programmer's Guide: https://doc.dpdk.org/guides/prog_guide/
