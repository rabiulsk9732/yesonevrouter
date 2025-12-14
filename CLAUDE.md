# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**YESRouter** is a high-performance, software-based Virtual Broadband Network Gateway (vBNG) for ISPs. It achieves 80 Gbps throughput on commodity x86 hardware using Intel DPDK for packet processing.

### Key Technologies
- **Intel DPDK** - High-performance packet processing (poll-mode drivers, zero-copy)
- **C/C++11** - Core implementation language
- **Linux Kernel 5.4+** - Foundation OS
- **CMake/Meson** - Build system
- **Systemd** - Service management

### Performance Targets
- Throughput: 80 Gbps
- Subscriber Capacity: 100,000+ concurrent subscribers
- Packet Rate: 200+ Mpps
- Session Setup: 10,000+ sessions/sec

## Quick Start

### Build Commands

```bash
# Create and navigate to build directory
mkdir -p build && cd build

# Configure with CMake
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_DPDK=ON \
  -DENABLE_TESTS=OFF \
  -DENABLE_ASAN=OFF

# Build (use 4 cores to avoid overwhelming system)
make -j4

# Or build specific targets
make yesrouterd          # Main daemon
make yesrouter           # CLI client
make yesroutercli        # Alternative CLI

# Run tests (if enabled)
make test
```

### Alternative: Meson Build

```bash
# Configure
meson setup builddir --buildtype=release

# Build
meson compile -C builddir

# Test
meson test -C builddir
```

### Build Options

**CMake Options:**
- `ENABLE_DPDK=ON/OFF` - Enable DPDK support (default: ON)
- `ENABLE_TESTS=ON/OFF` - Build unit tests (default: OFF)
- `ENABLE_BENCHMARKS=ON/OFF` - Build performance benchmarks (default: OFF)
- `ENABLE_ASAN=ON/OFF` - Enable AddressSanitizer (default: OFF)

**Compiler Flags:**
- Debug: `-g -O0 -DDEBUG -march=native`
- Release: `-O3 -march=native -mtune=native -funroll-loops -ffast-math -DNDEBUG`

## Architecture

### System Architecture (3 Planes)

```
┌─────────────────────────────────────────────┐
│         Management Plane                     │
│  (CLI, Web UI, REST API, NETCONF/YANG)      │
└─────────────────────────────────────────────┘
                    ▲
                    │ Control Signals
                    │
┌──────────────────────────────────────────────┐
│      Control Plane                           │
│  ┌──────────┐  ┌─────────┐  ┌────────────┐ │
│  │Routing   │  │BGP      │  │ Session    │ │
│  │Table Mgr │  │Engine   │  │ Manager    │ │
│  └──────────┘  └─────────┘  └────────────┘ │
└──────────────────────────────────────────────┘
                    ▲
                    │ Forwarding Decisions
                    │
┌──────────────────────────────────────────────┐
│         Data Plane (DPDK)                    │
│  ┌─────────────────────────────────────────┐ │
│  │ RX → Classify → Filter → NAT → Lookup  │ │
│  │    → QoS → TX                           │ │
│  └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
         │         │         │
      [Subscribers] [Uplink] [Management]
```

### Core Modules

1. **vBNG (Virtual Broadband Network Gateway)**
   - Subscriber session termination (PPPoE, IPoE)
   - Location: `src/pppoe/`, `src/ipoe/`, `src/access/`
   - Capacity: 128,000+ concurrent subscribers

2. **Firewall Module**
   - Stateful packet inspection and ACLs
   - Location: `src/security/`, `src/forwarding/`
   - Performance: <1μs per packet decision

3. **CGNAT (Carrier-Grade NAT)**
   - Network address translation at scale
   - Location: `src/nat/`
   - Features: SNAT44, DNAT44, session logging

4. **QoS Module**
   - Traffic classification and scheduling
   - Location: `src/qos/`, `src/hqos/`
   - Algorithms: Token bucket, WFQ, Strict Priority

5. **Routing Module**
   - IP packet forwarding and routing
   - Location: `src/routing/`
   - Protocols: BGP, Static routes, ECMP

6. **Data Plane Module**
   - High-performance packet processing
   - Location: `src/dpdk/`, `src/forwarding/`, `src/packet_rx.c`
   - Technology: Intel DPDK

7. **Management Module**
   - System configuration and monitoring
   - Location: `src/core/`, `src/management/`, `src/cli/`
   - Interfaces: CLI, Web UI, REST API

### Source Code Structure

```
src/
├── core/              # Core initialization and main loop
│   ├── main.c         # Entry point, initialization sequence
│   └── cpu_scheduler.c # CPU core allocation
├── cli/               # Command-line interface
│   ├── vty.c          # Virtual terminal (Cisco IOS-style)
│   ├── cli_system.c   # System commands
│   ├── cli_interface.c # Interface commands
│   ├── cli_nat.c      # NAT commands
│   ├── cli_pppoe.c    # PPPoE commands
│   └── cli_radius.c   # RADIUS commands
├── pppoe/             # PPPoE protocol implementation
│   ├── pppoe.c        # PPPoE state machine
│   ├── ppp_auth.c     # PAP/CHAP authentication
│   ├── ppp_lcp.c      # LCP protocol
│   └── pppoe_tx.c     # Transmit path
├── nat/               # Carrier-Grade NAT
│   ├── nat.c          # NAT core
│   ├── nat_session.c  # Session tracking
│   └── nat_translate.c # Translation engine
├── ipoe/              # IP over Ethernet (DHCP)
├── forwarding/        # Packet forwarding pipeline
│   └── packet_rx.c    # RX path (DPDK poll-mode)
├── interfaces/        # Interface management
├── network/           # ARP, IP reassembly, fragmentation
│   ├── reassembly.c   # IP packet reassembly (DPDK rte_ip_frag)
│   └── fragmentation.c # IP fragmentation
├── radius/            # RADIUS client
│   └── radius_lockless.c # Lockless RADIUS (high performance)
├── qos/               # Quality of Service
└── hqos/              # Hierarchical QoS
```

### Key Configuration Files

- **Service Configuration**: `/etc/systemd/system/yesrouter.service`
- **Environment Config**: `/etc/yesrouter/yesrouter.env` (Bison-style .env format)
- **Runtime Config**: `/etc/yesrouter/startup.json`
- **CLI Socket**: `/run/yesrouter/cli.sock`

## Development Workflow

### 1. System Service Management

```bash
# Start service
systemctl start yesrouter.service

# Check status
systemctl status yesrouter.service

# View logs
journalctl -u yesrouter.service -f

# Stop service
systemctl stop yesrouter.service

# Restart (after code changes)
systemctl restart yesrouter.service
```

**IMPORTANT**: Service uses `yesrouterd` binary, NOT `yesrouter`. The `yesrouter` command is the CLI client that connects to the daemon via Unix socket.

### 2. CLI Usage

```bash
# Connect to daemon (interactive mode)
yesrouter

# Execute single command
yesrouter show version
yesrouter show interfaces
yesrouter show interfaces brief
yesrouter show nat statistics
yesrouter show pppoe sessions

# Available commands (Cisco IOS-style):
show version
show interfaces [brief]
show pppoe sessions
show pppoe statistics
show nat statistics
show radius statistics
configure terminal    # Enter config mode
interface eth0        # Enter interface config mode
```

### 3. Testing

```bash
# Run Phase 1 tests
cd build
cmake .. -DENABLE_TESTS=ON
make test_phase1_build test_phase1_dpdk test_phase1_packet \
      test_phase1_config test_phase1_logging test_phase1_interfaces

# Run individual tests
./tests/test_phase1_build
./tests/test_phase1_dpdk
./tests/test_phase1_packet
./tests/test_phase1_config

# Performance tests (if available)
./tests/perf/*
```

### 4. DPDK Configuration

**Prerequisites:**
```bash
# Check hugepages
cat /proc/meminfo | grep HugePages
# Should show: HugePages_Total: 2048 (or more)

# Bind NICs to vfio-pci (example)
dpdk-devbind.py --bind=vfio-pci 0000:06:13.0 0000:06:14.0

# Check VFIO module
lsmod | grep vfio
```

**Environment Config** (`/etc/yesrouter/yesrouter.env`):
```bash
# CORES & MEMORY
MAIN_LCORE=0
WORKER_LCORES=1,2,3,4
MEMORY_MB=2048

# PORTS (PCI addresses)
PCI=(
    0000:06:13.0  # WAN
    0000:06:14.0  # LAN
)

# QUEUES
RX_QUEUES=4
TX_QUEUES=4
DPDK_RSS_ENABLE=true

# LOGGING
LOG_LEVEL=info
```

## Common Tasks

### Adding a New CLI Command

1. **Define command** in appropriate `cli_*.c` file:
```c
DEFUN(show_my_feature,
      show_my_feature_cmd,
      "show my feature",
      SHOW_STR "My feature information\n",
      FUNCWrapper(my_show_function))
```

2. **Implement handler**:
```c
int my_show_function(struct vty *vty, int argc, const char **argv) {
    vty_out(vty, "Feature status: active\n");
    return CMD_SUCCESS;
}
```

3. **Register in init** (same file):
```c
void cli_myfeature_init(void) {
    install_element(VIEW_NODE, &show_my_feature_cmd);
    install_element(ENABLE_NODE, &show_my_feature_cmd);
}
```

4. **Call init** from `src/cli/vty.c:cli_init()`:
```c
void cli_myfeature_init(void);  // Add declaration
// In cli_init():
cli_myfeature_init();           // Add call
```

### Adding a New Module

1. **Create directory**: `src/newmodule/`
2. **Add sources** to `CMakeLists.txt`
3. **Create header**: `include/newmodule.h`
4. **Implement init/cleanup** functions
5. **Call from** `src/core/main.c`:
   - Add initialization after `config_init()`
   - Add cleanup in reverse order before `log_cleanup()`

### Debugging

```bash
# Build with debug symbols
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Run with gdb
gdb --args ./build/yesrouterd --daemon

# Enable DPDK debug
export DPDK_LOG_LEVEL=debug

# Check core dumps
coredumpctl list
coredumpctl gdb yesrouterd

# System logs
journalctl -u yesrouter.service --no-pager -n 100
dmesg | tail -50
```

## Known Issues & Solutions

### Issue 1: Service Won't Start (Crash Loop)

**Symptoms:**
- `systemctl status yesrouter.service` shows "auto-restart" or exit-code 1
- Daemon crashes immediately on startup

**Diagnosis:**
```bash
# Check logs
journalctl -u yesrouter.service -n 100 --no-pager

# Try running manually
/root/yesonevrouter/build/yesrouterd --daemon
```

**Common Causes:**
1. **Wrong binary in service file**: Check `/etc/systemd/system/yesrouter.service` has `ExecStart=/root/yesonevrouter/build/yesrouterd --daemon` (not `yesrouter`)
2. **Missing IP reassembly initialization**: Ensure `ip_reassembly_init()` is called in `src/core/main.c`
3. **DPDK port initialization failure**: Check PCI devices are bound to vfio-pci
4. **Missing hugepages**: Configure with `echo 2048 > /proc/sys/vm/nr_hugepages`

### Issue 2: CLI Commands Cause Segmentation Fault

**Symptoms:**
- Service starts successfully
- Running any CLI command crashes the daemon with SIGSEGV
- Logs show: `segfault ... librte_ip_frag.so`

**Diagnosis:**
```bash
# Check kernel logs
dmesg | grep segfault

# Look for NULL pointer dereference in IP fragmentation
```

**Solution:**
The IP reassembly subsystem must be initialized before DPDK. Add to `src/core/main.c`:
```c
/* Initialize IP Reassembly subsystem for fragment processing */
extern int ip_reassembly_init(void);
if (ip_reassembly_init() != 0) {
    YLOG_ERROR("Failed to initialize IP reassembly subsystem");
    goto cleanup;
}
```

And cleanup:
```c
extern void ip_reassembly_cleanup(void);
ip_reassembly_cleanup();
```

### Issue 3: DPDK Port Initialization Fails

**Symptoms:**
- "EAL: Requested device XXXX:XX.X cannot be used"
- "eth_virtio_pci_init(): Failed to init PCI device"

**Solution:**
```bash
# Check device binding
dpdk-devbind.py --status

# Bind to vfio-pci
dpdk-devbind.py --bind=vfio-pci 0000:06:13.0 0000:06:14.0

# Or to uio_pci_generic
modprobe uio_pci_generic
dpdk-devbind.py --bind=uio_pci_generic 0000:06:13.0 0000:06:14.0

# Verify
lspci -nn | grep Virtio
ls -la /sys/bus/pci/devices/0000:06:13.0/driver
```

## Code Style & Conventions

### Naming Conventions
- **Functions**: `snake_case()` - lowercase with underscores
- **Variables**: `snake_case` - lowercase with underscores
- **Constants**: `UPPER_CASE` - uppercase with underscores
- **Structs**: `struct_name` - lowercase with underscores
- **Enums**: `enum_name` - lowercase with underscores
- **Macros**: `UPPER_CASE` - uppercase with underscores

### Code Structure
- **Public headers**: `include/` directory
- **Private headers**: `src/` directory with `.h` extension
- **One module per directory**: Each major subsystem has its own directory
- **Initialization**: Each module exports `module_init()` and `module_cleanup()`
- **Logging**: Use `YLOG_INFO()`, `YLOG_ERROR()`, `YLOG_DEBUG()` macros

### Logging
```c
// Available log levels
YLOG_EMERG   // System is unusable
YLOG_ALERT   // Action must be taken immediately
YLOG_CRIT    // Critical conditions
YLOG_ERROR   // Error conditions
YLOG_WARNING // Warning conditions
YLOG_NOTICE  // Normal but significant condition
YLOG_INFO    // Informational
YLOG_DEBUG   // Debug-level messages

// Usage examples
YLOG_INFO("Interface %s initialized", iface->name);
YLOG_ERROR("Failed to allocate memory for %s", object);
YLOG_DEBUG("Packet received on port %u", port_id);
```

### Error Handling
- Return `-1` on error, `0` on success (POSIX convention)
- Use `goto cleanup` pattern for resource cleanup
- Log errors with `YLOG_ERROR()` before returning
- Always check return values of system calls

### DPDK-Specific Conventions
- **Port IDs**: DPDK port number (0, 1, 2, ...)
- **Interface Names**: Linux network interface names (eth0, eth1, ...)
- **LCores**: Logical CPU cores (0-31 typically)
- **NUMA**: Socket ID 0 for single-socket systems
- **Memory Pools**: Named with `_POOL` suffix
- **RX/TX Queues**: Per-port receive/transmit queues

## Performance Optimization

### Key Performance Points

1. **Packet Processing**:
   - DPDK poll-mode drivers (no interrupts)
   - CPU affinity pinning
   - NUMA-aware memory allocation
   - Huge pages (2MB or 1GB)

2. **Memory Management**:
   - Pre-allocated mbuf pools
   - Lockless ring buffers
   - Per-worker data structures
   - Cache line alignment

3. **Lock Contention**:
   - Use per-worker threading
   - Lockless algorithms where possible
   - Minimize shared data structures
   - Use atomic operations

### Performance Monitoring

```bash
# CPU usage per core
top -d 1

# NIC statistics
cat /proc/net/dev

# DPDK port statistics
yesrouter show interfaces

# NAT session count
yesrouter show nat statistics

# Check CPU affinity
ps -eo pid,psr,comm | grep yesrouterd
```

## Troubleshooting Guide

### Service Won't Start
```bash
# Check service status
systemctl status yesrouter.service

# View detailed logs
journalctl -u yesrouter.service --no-pager -n 100

# Check configuration
cat /etc/yesrouter/yesrouter.env

# Verify binaries exist
ls -la /root/yesonevrouter/build/yesrouterd
ls -la /usr/local/bin/yesrouter

# Check PCI devices
lspci -nn | grep Virtio
dpdk-devbind.py --status

# Verify hugepages
cat /proc/meminfo | grep HugePages
```

### High CPU Usage
```bash
# Check which cores are busy
mpstat -P ALL 1

# Check interrupt rate
cat /proc/interrupts

# Verify DPDK is in poll mode (no interrupts)
# Should see low interrupt count
```

### Memory Issues
```bash
# Check hugepages usage
cat /proc/meminfo | grep -i huge

# Check DPDK memory
cat /proc/meminfo | grep -i mempool

# Monitor memory growth
watch -n 1 'cat /proc/meminfo | grep -i mem'
```

### Network Issues
```bash
# Check interface status
yesrouter show interfaces

# Check NAT translation table
yesrouter show nat sessions

# Monitor packet rates
yesrouter show interfaces statistics

# Check DPDK port stats
cat /sys/class/net/eth0/statistics/rx_bytes
cat /sys/class/net/eth0/statistics/tx_bytes
```

## Documentation

### Available Documentation

- **README.md** - Project overview and quick start
- **docs/README.md** - Detailed project documentation
- **docs/ARCHITECTURE.md** - System architecture and design
- **docs/MODULES_BREAKDOWN.md** - Detailed module specifications (50 pages)
- **docs/CLI_ARCHITECTURE.md** - CLI implementation details
- **docs/QUICK_REFERENCE.md** - Fast lookup for commands and config
- **docs/INDEX.md** - Master index for all documentation
- **tests/RUN_TESTS.md** - Test execution instructions

### Documentation Best Practices

1. **For new features**: Document in appropriate `docs/*.md` file
2. **For API changes**: Update `QUICK_REFERENCE.md`
3. **For architecture**: Update `ARCHITECTURE.md`
4. **For modules**: Update `MODULES_BREAKDOWN.md`

## Advanced Topics

### Multi-Process DPDK
The codebase supports DPDK multi-process mode for separating control plane and data plane:

- **Primary process**: Control plane, management, CLI
- **Secondary processes**: Data plane packet processing
- **Communication**: DPDK IPC (multi-process socket)

### High Availability
- Active/Standby configuration possible
- State synchronization via shared memory
- Gratuitous ARP for failover
- RADIUS request replication

### IPv6 Support
- Dual-stack operation (IPv4 + IPv6)
- IPv6 routing and forwarding
- IPv6 firewall rules
- NAT64/DNS64 (planned)

---

**Status**: Last updated December 14, 2024
**Version**: 1.0.0
**Maintainer**: YESRouter Development Team

For questions not covered in this guide, consult the documentation in `docs/` or review the source code in `src/`.
