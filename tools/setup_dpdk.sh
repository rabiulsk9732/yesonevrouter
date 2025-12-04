#!/bin/bash
# setup_dpdk.sh - DPDK Environment Setup Script
#
# This script sets up the environment for DPDK execution:
# 1. Reserves hugepages
# 2. Loads DPDK kernel modules (uio, igb_uio/vfio-pci)
# 3. Binds network interfaces to DPDK driver
#
# Usage: ./setup_dpdk.sh [interface_pci_id] ...

set -e

# Configuration
HUGEPAGES=1024
HUGEPAGE_MOUNT=/mnt/huge
DRIVER=vfio-pci # or igb_uio

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "========================================"
echo "DPDK Environment Setup"
echo "========================================"

# 1. Reserve Hugepages
echo "[1] Configuring Hugepages..."
echo $HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
echo "    Reserved $(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages) hugepages"

# Mount hugetlbfs if not already mounted
if ! mount | grep -q "$HUGEPAGE_MOUNT"; then
    mkdir -p $HUGEPAGE_MOUNT
    mount -t hugetlbfs nodev $HUGEPAGE_MOUNT
    echo "    Mounted hugetlbfs at $HUGEPAGE_MOUNT"
else
    echo "    Hugetlbfs already mounted at $HUGEPAGE_MOUNT"
fi

# 2. Load Kernel Modules
echo "[2] Loading Kernel Modules..."
modprobe vfio-pci
echo "    Loaded vfio-pci"

# 3. Bind Interfaces
if [ $# -eq 0 ]; then
    echo "[3] No interfaces specified to bind."
    echo "    Usage: $0 <pci_bus_id> ..."
    echo "    Example: $0 0000:03:00.0 0000:03:00.1"
else
    echo "[3] Binding Interfaces to $DRIVER..."
    for pci_id in "$@"; do
        echo "    Binding $pci_id..."
        # Note: This assumes dpdk-devbind.py is in path or use manual bind
        if command -v dpdk-devbind.py &> /dev/null; then
            dpdk-devbind.py --bind=$DRIVER $pci_id
        else
            # Manual bind
            echo $DRIVER > /sys/bus/pci/devices/$pci_id/driver_override
            echo $pci_id > /sys/bus/pci/drivers/$DRIVER/bind
            echo $pci_id > /sys/bus/pci/drivers/$DRIVER/new_id 2>/dev/null || true
        fi
    done
fi

echo "========================================"
echo "Setup Complete"
echo "========================================"
echo "To run YESRouter with DPDK:"
echo "  ./yesrouter -l 0-1 -n 4 -- -c config.conf"
