# Testing NAT After Fix

## Quick Verification Steps

### 1. Check NAT Configuration
```bash
yesrouterctl show nat config
```

**Expected output:**
```
NAT Configuration:
  Status: Enabled
  Hairpinning: Disabled
  EIM: Enabled
  Deterministic NAT: Disabled

  NAT Pools (1):
    WAN-POOL: <WAN_IP> - <WAN_IP> (1 IPs, 0 used)
```

**If Status shows "Disabled" or Pools shows "(0)":**
```bash
yesrouterctl
nat pool WAN-POOL <YOUR_WAN_IP> <YOUR_WAN_IP> netmask 255.255.255.255
nat enable
show nat config
```

### 2. Check Routing Table
```bash
yesrouterctl show ip route
```

Should show default route (0.0.0.0/0) pointing to WAN gateway.

### 3. Check Interfaces
```bash
yesrouterctl show interfaces
```

Verify:
- LAN interface (Gi0/2) has IP 172.16.17.1
- WAN interface (Gi0/1) has your public IP
- Both are UP

### 4. Test from Client (172.16.17.2)
```bash
# From client machine
ping 1.1.1.1
```

### 5. Monitor NAT Activity
While client is pinging, check NAT:

```bash
yesrouterctl show nat translations
yesrouterctl show nat statistics
```

**Expected:**
- `show nat translations` should show active sessions with:
  - Inside IP: 172.16.17.2
  - Outside IP: Your WAN IP
  - Protocol: ICMP (or TCP/UDP if testing other protocols)

- `show nat statistics` should show:
  - `Packets translated: > 0`
  - `SNAT packets: > 0`
  - `Active sessions: > 0`

### 6. Check Logs for NAT Activity
```bash
# Check system logs for NAT debug messages
journalctl -u yesrouter -f | grep -i nat
```

Look for:
- "NAT SNAT applied" - NAT is working
- "NAT SNAT failed" - Check error details
- "needs NAT but NAT is disabled" - Configuration issue

## Troubleshooting

### If NAT translations show 0 sessions:

1. **Check if NAT is enabled:**
   ```bash
   yesrouterctl show nat config
   ```

2. **Check if pool exists:**
   ```bash
   yesrouterctl show nat config
   ```
   Look for "NAT Pools (1):" with at least one pool

3. **Check error counters:**
   ```bash
   yesrouterctl show nat statistics
   ```
   Look for:
   - `no_ip_available` - No pool configured
   - `no_port_available` - Port exhaustion (unlikely)
   - `invalid_packet` - Protocol not supported

4. **Check interface indexes:**
   ```bash
   yesrouterctl show interfaces
   ```
   Note the index numbers. The new code should work regardless, but good to verify.

5. **Generate traffic and check logs:**
   ```bash
   # From client: ping 1.1.1.1
   # Then check:
   journalctl -u yesrouter --since "1 minute ago" | grep -i nat
   ```

### If you see "NAT SNAT failed" in logs:

The new code will show detailed error:
```
NAT SNAT failed for packet from 172.16.17.2 (ingress=2, egress=1, pools=0)
```

This tells you:
- Source IP: 172.16.17.2
- Ingress interface index: 2
- Egress interface index: 1
- Number of pools: 0 (this is the problem!)

**Fix:**
```bash
yesrouterctl
nat pool WAN-POOL <WAN_IP> <WAN_IP> netmask 255.255.255.255
show nat config
```

### If you see "needs NAT but NAT is disabled":

This means:
- Private IP detected (172.16.17.2)
- But NAT is disabled or no pool configured

**Fix:**
```bash
yesrouterctl
nat pool WAN-POOL <WAN_IP> <WAN_IP> netmask 255.255.255.255
nat enable
show nat config
```

## Expected NAT Flow

1. **Client sends packet:**
   - Source: 172.16.17.2
   - Destination: 1.1.1.1

2. **Router receives on LAN interface:**
   - Detects private IP (172.16.17.2)
   - Applies SNAT
   - Translates source to WAN IP
   - Forwards to WAN

3. **Return traffic:**
   - Source: 1.1.1.1
   - Destination: WAN IP:port
   - Router applies DNAT
   - Translates destination back to 172.16.17.2
   - Forwards to LAN

## Quick Test Script

```bash
#!/bin/bash
# Quick NAT test

echo "=== NAT Configuration ==="
yesrouterctl show nat config

echo ""
echo "=== Routing Table ==="
yesrouterctl show ip route

echo ""
echo "=== Interfaces ==="
yesrouterctl show interfaces

echo ""
echo "=== NAT Statistics (before) ==="
yesrouterctl show nat statistics

echo ""
echo "Now generate traffic from client (ping 1.1.1.1), then run:"
echo "  yesrouterctl show nat translations"
echo "  yesrouterctl show nat statistics"
```
