#!/bin/bash
###############################################################################
# DPDK Production Setup - Master Installer
# Runs all installation steps in order
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================"
echo "  DPDK Production Environment - Complete Setup"
echo "  Ubuntu 22.04 LTS | DPDK 23.11 LTS"
echo "========================================================"
echo ""

if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root (sudo)"
   exit 1
fi

cd ${SCRIPT_DIR}

echo "Step 1/4: System Update and Dependencies"
echo "========================================="
bash 01-system-setup.sh

echo ""
echo "Step 2/4: Hugepages Configuration"
echo "=================================="
bash 02-configure-hugepages.sh

echo ""
echo "Step 3/4: DPDK Installation"
echo "==========================="
bash 03-install-dpdk.sh

echo ""
echo "Step 4/4: Interface Binding Setup"
echo "=================================="
bash 04-bind-interfaces.sh

echo ""
echo "========================================================"
echo "  DPDK Installation Complete!"
echo ""
echo "  DPDK Version: 23.11 LTS (Production Grade)"
echo "  Hugepages: Configured"
echo "  Drivers: vfio-pci / uio_pci_generic"
echo ""
echo "  IMPORTANT: Reboot recommended for optimal performance"
echo "  - Hugepages will be allocated at boot"
echo "  - IOMMU settings will be active"
echo ""
echo "  Helper commands:"
echo "    dpdk-nic-status     - Show NIC status"
echo "    dpdk-bind-nic       - Bind NIC to DPDK"
echo "    dpdk-unbind-nic     - Restore NIC to kernel"
echo "========================================================"
