# YESRouter vBNG - Virtual Broadband Network Gateway

High-performance software-based Virtual Broadband Network Gateway (vBNG) for ISPs.

## Features

- **80 Gbps throughput** on commodity x86 hardware
- **100,000+ concurrent subscribers** per system
- **PPPoE and IPoE** session termination
- **Carrier-Grade NAT (CGNAT)** with logging
- **QoS** traffic classification and shaping
- **Stateful firewall** with ACLs
- **BGP routing** protocol support
- **Intel DPDK** based data plane

## Prerequisites

- Linux kernel 5.4+
- GCC 9.0+ or Clang 10+
- CMake 3.16+ or Meson 0.55+
- Intel DPDK 21.11+ (optional but recommended)
- libyang (for configuration)

## Quick Start

### Building with CMake

```bash
# Create build directory
mkdir build && cd build

# Configure
cmake ..

# Build
make -j$(nproc)

# Run tests
make test
```

### Building with Meson

```bash
# Configure
meson setup builddir

# Build
meson compile -C builddir

# Run tests
meson test -C builddir
```

## Build Options

### CMake Options
- `ENABLE_DPDK=ON/OFF` - Enable DPDK support (default: ON)
- `ENABLE_TESTS=ON/OFF` - Build unit tests (default: ON)
- `ENABLE_BENCHMARKS=ON/OFF` - Build performance benchmarks (default: OFF)
- `ENABLE_ASAN=ON/OFF` - Enable AddressSanitizer (default: OFF)

### Meson Options
- `buildtype=debug/release` - Build type (default: release)

## Project Structure

```
vbng/
├── src/              # Source code
│   ├── core/         # Core packet processing
│   ├── dpdk/         # DPDK integration
│   ├── config/       # Configuration management
│   ├── logging/      # Logging framework
│   ├── interfaces/   # Interface abstraction
│   ├── routing/      # Routing table
│   ├── bgp/          # BGP protocol
│   ├── network/      # ARP/Neighbor
│   ├── forwarding/   # Packet forwarding
│   ├── access/       # PPPoE/IPoE
│   ├── session/      # Session management
│   ├── firewall/     # Firewall & ACL
│   ├── cgnat/        # Carrier-Grade NAT
│   ├── qos/          # Quality of Service
│   └── management/   # Management APIs
├── include/          # Public headers
├── tests/            # Unit tests
├── docs/             # Documentation
├── scripts/          # Build and deployment scripts
└── build/            # Build artifacts
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - System architecture overview
- [Modules Breakdown](docs/MODULES_BREAKDOWN.md) - Detailed module specifications
- [Implementation Tasks](docs/IMPLEMENTATION_TASKS.md) - Implementation roadmap
- [Quick Reference](docs/QUICK_REFERENCE.md) - Fast lookup guide
- [Task Tracker](docs/task.md) - Implementation progress tracker

## Development Status

This project is currently under active development. See [task.md](docs/task.md) for implementation progress.

**Current Phase**: Phase 1 - Foundation & Core Infrastructure

## License

[To be determined]

## Contributing

Contributions are welcome! Please read the documentation in the `docs/` directory before contributing.

## Performance Targets

| Metric | Target |
|--------|--------|
| Throughput | 80 Gbps |
| Subscribers | 100,000+ |
| Session Setup Rate | 10,000+ sessions/sec |
| Packet Rate | 200+ Mpps |
| Latency | < 100 μs |

## Contact

For questions and support, please refer to the documentation.
