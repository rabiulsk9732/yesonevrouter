# Fix for NAT and Routing Issues

## Problem Summary
Client at 172.16.17.2 can ping router (172.16.17.1) but cannot reach external IPs (1.1.1.1). Getting "Destination Host Unreachable" errors.

## Root Causes

### 1. **Missing Default Route**
The router has no default route (0.0.0.0/0) configured, so packets to external destinations are dropped.

### 2. **NAT Not Enabled/Configured**
Even with a route, NAT must be enabled and a NAT pool configured for client traffic to work.

### 3. **ICMP Error Handling**
The router now sends ICMP Destination Unreachable when no route is found (code fix applied).

## Solution Steps

### Step 1: Add Default Route
Connect via yesrouterctl and add a default route pointing to your WAN gateway:

```bash
yesrouterctl
show ip route                    # Check current routes
route add 0.0.0.0/0 via <WAN_GATEWAY_IP>
show ip route                    # Verify route added
```

**Example:**
```bash
yesrouterctl
route add 0.0.0.0/0 via 103.174.247.65
```

**Note:** Replace `103.174.247.65` with your actual WAN gateway IP.

### Step 2: Configure NAT Pool
Create a NAT pool with your public WAN IP:

```bash
yesrouterctl
nat pool WAN-POOL <WAN_IP> <WAN_IP> netmask 255.255.255.255
show nat config
```

**Example:**
```bash
yesrouterctl
nat pool WAN-POOL 103.174.247.67 103.174.247.67 netmask 255.255.255.255
```

### Step 3: Enable NAT
Enable NAT globally:

```bash
yesrouterctl
nat enable
show nat config
```

### Step 4: Verify Configuration
Check everything is configured correctly:

```bash
yesrouterctl <<EOF
show ip route
show nat config
show interfaces
EOF
```

**Expected Output:**
```
IP Route Table:
  0.0.0.0/0 via 103.174.247.65 (static) [Gi0/1]

NAT Configuration:
  Status: Enabled
  NAT Pools (1):
    WAN-POOL: 103.174.247.67 - 103.174.247.67 (1 IPs, 0 used)

Interfaces:
  Gi0/1: 103.174.247.67/26 (WAN) - UP
  Gi0/2: 172.16.17.1/24 (LAN) - UP
```

### Step 5: Test from Client
From client (172.16.17.2):
```bash
ping 1.1.1.1
```

Should now work! Check NAT translations:
```bash
yesrouterctl
show nat translations
show nat statistics
```

## Complete Configuration Script

```bash
#!/bin/bash
# Complete NAT and routing setup

WAN_GATEWAY="103.174.247.65"  # Change to your WAN gateway
WAN_IP="103.174.247.67"        # Change to your WAN IP

yesrouterctl <<EOF
# Add default route
route add 0.0.0.0/0 via $WAN_GATEWAY

# Configure NAT pool
nat pool WAN-POOL $WAN_IP $WAN_IP netmask 255.255.255.255

# Enable NAT
nat enable

# Verify
show ip route
show nat config
show interfaces
EOF
```

## Troubleshooting

### If still not working:

1. **Check routing table:**
   ```bash
   yesrouterctl show ip route
   ```
   Should show `0.0.0.0/0` route.

2. **Check NAT status:**
   ```bash
   yesrouterctl show nat config
   ```
   Should show "Enabled" and at least one pool.

3. **Check interface indexes:**
   ```bash
   yesrouterctl show interfaces
   ```
   Gi0/1 should be index 1 (WAN), Gi0/2 should be index 2 (LAN).

4. **Check NAT statistics:**
   ```bash
   yesrouterctl show nat statistics
   ```
   Look for error counters like `no_ip_available` or `no_port_available`.

5. **Check ARP:**
   ```bash
   yesrouterctl show arp
   ```
   Should have ARP entry for WAN gateway.

6. **Generate traffic and check translations:**
   ```bash
   # From client: ping 1.1.1.1
   # Then check:
   yesrouterctl show nat translations
   ```

## Code Changes Made

1. **Added ICMP Destination Unreachable** (`packet_rx.c`):
   - When no route is found, router now sends ICMP error back to client
   - This explains why client sees "Destination Host Unreachable"

2. **Function added:** `send_icmp_destination_unreachable()`
   - Sends ICMP Type 3 (Destination Unreachable)
   - Code 0 = Network Unreachable (no route)

## Next Steps

After applying the configuration:
1. Test ping from client to external IP
2. Monitor NAT translations
3. Check NAT statistics for any errors
4. Verify packets are being translated correctly
