# NAT Troubleshooting Guide

## Common Issues and Solutions

### Issue 1: NAT is Disabled by Default
**Problem:** NAT is disabled by default when yesrouter starts.

**Solution:**
```bash
yesrouterctl
nat enable
show nat config
```

**Check:** Verify NAT status shows "Enabled"

### Issue 2: No NAT Pool Configured
**Problem:** NAT requires at least one pool to be configured. If no pool exists, NAT will fail with "no_ip_available" error.

**Solution:**
```bash
yesrouterctl
nat pool WAN-POOL <public-ip-start> <public-ip-end> netmask <netmask>
# Example:
nat pool WAN-POOL 103.174.247.67 103.174.247.67 netmask 255.255.255.255
show nat config
```

**Check:** Verify "NAT Pools" shows at least 1 pool with IPs available.

### Issue 3: Interface Index Mismatch
**Problem:** The code assumes interface index 1 is WAN. If interfaces are created in different order, NAT might not apply correctly.

**Check interface indexes:**
```bash
yesrouterctl
show interfaces
```

**Expected:**
- Gi0/1 should be index 1 (WAN)
- Gi0/2 should be index 2 (LAN)

**If wrong order:** Recreate interfaces in correct order or update the code logic.

### Issue 4: NAT Not Applied to Packets
**Problem:** NAT is only applied when:
1. NAT is enabled (`nat_is_enabled()` returns true)
2. Both ingress and egress interfaces exist
3. Ingress interface is NOT index 1 (WAN)
4. A NAT pool exists with available IPs

**Debug steps:**
```bash
yesrouterctl
show nat config          # Check if enabled and pool exists
show nat statistics      # Check if packets are being translated
show nat translations    # Check if sessions are being created
```

### Issue 5: Port Allocation Failure
**Problem:** If all ports are exhausted, NAT will fail.

**Check:**
```bash
yesrouterctl
show nat statistics
```

Look for:
- `no_port_available` counter
- Active sessions count

### Issue 6: Session Creation Failure
**Problem:** NAT session table might be full or there's a memory issue.

**Check:**
```bash
yesrouterctl
show nat statistics
clear nat translations   # Clear old sessions if needed
```

## Diagnostic Commands

### Full NAT Status Check
```bash
yesrouterctl <<EOF
show nat config
show nat statistics
show nat translations
show interfaces
EOF
```

### Enable and Configure NAT
```bash
yesrouterctl <<EOF
nat pool WAN-POOL 103.174.247.67 103.174.247.67 netmask 255.255.255.255
nat enable
show nat config
EOF
```

### Monitor NAT Activity
```bash
# Generate traffic from client, then check:
yesrouterctl show nat translations
yesrouterctl show nat statistics
```

## Expected Output

### When NAT is Working:
```
NAT Configuration:
  Status: Enabled
  Hairpinning: Disabled
  EIM: Enabled
  Deterministic NAT: Disabled

  NAT Pools (1):
    WAN-POOL: 103.174.247.67 - 103.174.247.67 (1 IPs, 0 used)

  Statistics:
    Total sessions: 10
    Active sessions: 5
    Sessions created: 10
    Packets translated: 150
    SNAT packets: 75
    DNAT packets: 75
```

### When NAT is NOT Working:
```
NAT Configuration:
  Status: Disabled    <-- PROBLEM: Need to enable
  ...
  NAT Pools (0):      <-- PROBLEM: Need to create pool
```

## Code Locations

- NAT enable/disable: `src/cli/cli_nat.c` lines 102-122
- NAT initialization: `src/nat/nat_core.c` line 27 (disabled by default)
- NAT application: `src/forwarding/packet_rx.c` lines 280-290
- NAT translation: `src/nat/nat_translate.c` lines 73-197

## Quick Fix Script

```bash
#!/bin/bash
# Quick NAT setup script

yesrouterctl <<EOF
nat pool WAN-POOL 103.174.247.67 103.174.247.67 netmask 255.255.255.255
nat enable
show nat config
EOF
```
