# YESRouter vBNG - Project Knowledge

## Overview
YESRouter is a high-performance Virtual Broadband Network Gateway (vBNG) for ISPs, built on Intel DPDK for 80 Gbps throughput on commodity x86 hardware.

## Tech Stack
- **Language**: C (C11)
- **Build System**: CMake 3.16+, Meson 0.55+
- **Packet Processing**: Intel DPDK 21.11+
- **OS**: Linux (kernel 5.4+)
- **Compiler**: GCC 9.0+ or Clang 10+

## Project Structure
```
src/
├── core/          # Main entry, packet processing
├── dpdk/          # DPDK initialization
├── interfaces/    # Physical/virtual interface management
├── network/       # ARP, VLAN, LACP, DNS
├── routing/       # Routing table, BGP
├── forwarding/    # Packet RX/TX, session tables
├── nat/           # CG-NAT implementation
├── pppoe/         # PPPoE BNG server
├── radius/        # RADIUS authentication
├── qos/           # Traffic shaping, HQoS
├── ha/            # High availability, failover
├── cli/           # Cisco-style CLI
├── config/        # Configuration parsing
├── auth/          # User authentication
├── logging/       # Logging framework
└── management/    # REST API, metrics
```

## Key Files
- `src/core/main.c` - Entry point, DPDK initialization
- `src/cli/cli.c` - CLI command registration and execution
- `startup.conf` - VPP-style startup configuration
- `config/setup.gate` - Auto-executed CLI commands on boot

## Build Commands
```bash
# Quick build
./compile.sh

# Manual build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Run
./build/yesrouter
```

## CLI Style
Cisco IOS-style CLI with modes:
- User mode (`>`)
- Privileged mode (`#`) - enter with `enable`
- Config mode (`(config)#`) - enter with `configure terminal`
- Interface mode (`(config-if)#`)

## Current Implementation Status
- ✅ DPDK packet processing
- ✅ Interface management (physical, VLAN, LAG, dummy)
- ✅ ARP resolution
- ✅ IP routing with ECMP
- ✅ ICMP ping/traceroute
- ✅ CG-NAT (SNAT44, DNAT44, port blocks, deterministic)
- ✅ PPPoE BNG server
- ✅ RADIUS authentication
- ✅ QoS/HQoS
- ✅ High availability
- 🔄 CLI integration for VLAN/LACP
- ⏳ BGP protocol
