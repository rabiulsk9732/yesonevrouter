# YESRouter vBNG - Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-12-05

### Added

#### CLI Enhancements
- **Professional Banner**: Beautiful box-style welcome banner on CLI connection with version info
- **Mode-Aware Prompts**:
  - `yesrouter#` for privileged EXEC mode
  - `yesrouter(config)#` for configuration mode
  - `yesrouter(config-if-Gi0/1)#` for interface config mode
- **`save` Command**: Alias for `write memory` (follows VyOS/Juniper convention)
- **`commit` Command**: Validates and saves configuration (VyOS style)
- **`configure` without `terminal`**: Now works as shorthand

#### Configuration Persistence
- **Proper Config Save**: `write`/`save`/`commit` now saves to `/etc/yesrouter/startup.gate`
- **NAT Config Export**: Masquerade/NAT rules are saved and reloaded on boot
- **Auto-load on Restart**: Configuration persists across service restarts

#### NAT Improvements
- **IPFIX Export (RFC 7011/8158)**: Export NAT session events to IPFIX collectors
- **NetFlow v9 Export**: Export NAT events to legacy NetFlow v9 collectors
- **NAT Logging CLI**: `nat logging ipfix`, `nat logging netflow`, `show nat logging`
- **NAT Rule Storage**: Masquerade rules now properly stored in `g_nat_config.rules[]`
- **Policy-Based NAT**: Support for ACL-based NAT pool selection
- **Static NAT**: Port forwarding with permanent sessions (is_static flag)

### Fixed

#### Critical Fixes
- **Shutdown Crash**: Fixed segfault on service stop/restart
  - Added safety check for NAT timeout thread termination
  - Proper thread join with timeout before cleanup
- **NAT Translation Stability**: Fixed intermittent NAT failures after restart
  - Root cause: Segfault was corrupting state between restarts

#### Debug Spam Removed
- Removed `[RX DEBUG]` messages from packet_rx.c
- Removed `[RX LOOP DEBUG]` messages from packet_rx.c
- Removed `[PHY DEBUG]` messages from physical.c
- Removed `[ROUTE DEBUG]` and `[FWD DEBUG]` messages
- Removed `DEBUG: cli_execute` from cli.c

#### Build Fixes
- Added `-march=native` to debug build flags for DPDK compatibility
- Increased `DPDK_NUM_MBUFS` to 32767 for 32-core systems
- Fixed TX/RX queue clamping to prevent out-of-bounds access

### Changed

#### Code Quality
- Added spinlocks to physical interface for thread-safe TX/RX
- Improved error messages with file permissions hints
- Better config validation messages

#### Configuration
- `startup.gate` is now the canonical config file (not `startup-config`)
- Removed redundant `routing_table_init()` call in main.c

### Performance
- DPDK poll-mode driver properly utilizing configured cores
- NAT session lookup optimized with sharded locks
- Removed excessive debug printf calls from hot path

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2025-12-05 | Production-ready release with CLI refinements |
| 0.9.x | 2025-12-04 | NAT integration and testing |
| 0.8.x | 2025-12-03 | Core routing and interface management |

---

## Contributors
- Development and testing by YESRouter Team
- DPDK integration based on DPDK Programmer's Guide
- CLI design inspired by Cisco IOS and VyOS
