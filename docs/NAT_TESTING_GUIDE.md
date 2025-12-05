# NAT Testing Guide for YESRouter

## Overview
This guide explains how to test Source NAT (SNAT) configuration for allowing the LAN network (172.16.17.0/24) to access the internet using the WAN IP (103.174.247.67).

## NAT Configuration

The NAT configuration has been added to `startup.gate` and includes:
- NAT pool named "WAN-POOL" with public IP 103.174.247.67
- NAT enabled globally

## Commands to Test NAT

### 1. Check NAT Configuration
```
show nat config
```
This shows:
- NAT status (Enabled/Disabled)
- Configured NAT pools
- NAT statistics

### 2. Check NAT Statistics
```
show nat statistics
```
Shows detailed statistics including:
- Active sessions
- Packets translated
- SNAT/DNAT counters

### 3. Check Active NAT Translations
```
show nat translations
```
Shows active NAT sessions with:
- Inside IP:Port
- Outside IP:Port
- Protocol
- State

### 4. Clear NAT Translations (if needed)
```
clear nat translations
```

## Manual NAT Configuration (if not using startup.gate)

If you want to configure NAT manually:

```
configure terminal

! Create NAT pool with WAN IP
nat pool WAN-POOL 103.174.247.67 103.174.247.67 netmask 255.255.255.192

! Enable NAT globally
nat enable

end
```

## How NAT Works in YESRouter

1. **Inside to Outside (LAN to WAN)**:
   - Packet from 172.16.17.x goes to Gi0/2 (LAN interface)
   - NAT translates source IP 172.16.17.x → 103.174.247.67
   - Allocates a dynamic port for the translation
   - Forwards packet out Gi0/1 (WAN interface)

2. **Outside to Inside (Return Traffic)**:
   - Reply packet arrives on Gi0/1 with dest 103.174.247.67:port
   - NAT looks up session by outside IP:port
   - Translates destination 103.174.247.67:port → 172.16.17.x:original_port
   - Forwards back to LAN client

## Testing from CLI

### Method 1: Using ping (if router can ping)
```
ping 8.8.8.8
```

### Method 2: Check after traffic flows
1. Generate traffic from a LAN client (172.16.17.x)
2. Run: `show nat translations`
3. You should see NAT sessions created

## Expected NAT Pool Output

```
NAT Configuration:
  Status: Enabled
  ...
  NAT Pools (1):
    WAN-POOL: 103.174.247.67 - 103.174.247.67 (1 IPs, 0 used)
```

## Troubleshooting

### If NAT is not working:
1. Verify NAT is enabled: `show nat config`
2. Check interfaces are UP: `show interfaces brief`
3. Verify routing: `show ip route`
4. Check for NAT sessions: `show nat translations`

### Enable/Disable NAT
```
configure terminal
nat enable    # or nat disable
end
```

## Port Allocation

YESRouter uses dynamic port allocation:
- Port range: 10000-65000
- Round-robin allocation
- Automatic timeout for inactive sessions

## Advanced: Multiple Public IPs

To add more public IPs to the pool:
```
nat pool WAN-POOL 103.174.247.67 103.174.247.70 netmask 255.255.255.192
```
This creates a pool with 4 IPs for load distribution.

## Notes

- NAT sessions timeout after inactivity
- TCP: ~3600 seconds (1 hour)
- UDP: ~300 seconds (5 minutes)
- ICMP: ~60 seconds (1 minute)
- Port blocks can be allocated per subscriber for deterministic NAT
