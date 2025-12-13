# DPDK Production Environment Setup

Complete production-grade DPDK (Data Plane Development Kit) setup for **Ubuntu 22.04 LTS** with **DPDK 23.11 LTS**.

## DPDK Version: 23.11 LTS
- Long Term Support release
- Maintained until December 2026
- Recommended for production environments

## Quick Start

```bash
cd /root/.gemini/antigravity/scratch/dpdk-production
sudo chmod +x *.sh
sudo ./install-all.sh
```

## Step-by-Step Installation

### 1. System Setup (`01-system-setup.sh`)
- Full system update and upgrade
- Install build tools (gcc, make, cmake, meson, ninja)
- Install DPDK dependencies (libnuma, libpcap, libelf, etc.)
- Install Python tools and pyelftools

### 2. Hugepages Configuration (`02-configure-hugepages.sh`)
- Allocates 4GB of 2MB hugepages (configurable)
- Mounts hugetlbfs
- Makes configuration persistent across reboots
- Configures GRUB for boot-time allocation

### 3. DPDK Installation (`03-install-dpdk.sh`)
- Downloads DPDK 23.11.2 from official source
- Builds with production optimizations
- Installs to `/usr/local`
- Sets up environment variables
- Loads kernel modules (vfio-pci, uio)

### 4. Interface Binding (`04-bind-interfaces.sh`)
- Detects available NICs
- Creates helper scripts for binding/unbinding
- Supports both VFIO-PCI and UIO drivers

## Requirements
- Ubuntu 22.04 LTS
- Root/sudo access
- Network interfaces for packet processing
- Recommended: 8GB+ RAM, multi-core CPU

## Post-Installation
1. Reboot for optimal hugepage allocation
2. Bind NICs: `sudo dpdk-bind-nic 0000:XX:00.0`
3. Test: `cd sample_app && ./test_dpdk.sh`

## Helper Commands
| Command | Description |
|---------|-------------|
| `dpdk-nic-status` | Show all NIC binding status |
| `dpdk-bind-nic <pci>` | Bind NIC to DPDK driver |
| `dpdk-unbind-nic <pci>` | Restore NIC to kernel driver |
