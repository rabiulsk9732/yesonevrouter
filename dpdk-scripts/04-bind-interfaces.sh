#!/bin/bash
###############################################################################
# DPDK Production Environment Setup - Step 4: Bind Network Interfaces
# Binds NIC to DPDK-compatible driver (vfio-pci or uio_pci_generic)
###############################################################################

set -e
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (sudo)"
   exit 1
fi

echo "============================================================"
echo "  DPDK Production - Network Interface Binding"
echo "============================================================"
echo ""

###############################################################################
# DPDK devbind utility location
###############################################################################
DPDK_DEVBIND=""

# Search for dpdk-devbind.py in common locations
for path in \
    "/usr/local/bin/dpdk-devbind.py" \
    "/opt/dpdk/dpdk-*/usertools/dpdk-devbind.py" \
    "/usr/share/dpdk/usertools/dpdk-devbind.py" \
    "/usr/bin/dpdk-devbind"; do

    if compgen -G "$path" > /dev/null 2>&1; then
        DPDK_DEVBIND=$(ls $path 2>/dev/null | head -1)
        break
    fi
done

if [ -z "$DPDK_DEVBIND" ]; then
    log_error "dpdk-devbind.py not found!"
    log_info "Please ensure DPDK is properly installed"
    exit 1
fi

log_info "Using devbind: ${DPDK_DEVBIND}"

###############################################################################
# Step 1: Show current network device status
###############################################################################
echo ""
log_info "Current network device status:"
echo "========================================"
python3 ${DPDK_DEVBIND} --status-dev net
echo "========================================"

###############################################################################
# Step 2: Enable IOMMU (required for vfio-pci)
###############################################################################
log_info "Checking IOMMU status..."

if [ -d /sys/class/iommu ]; then
    IOMMU_GROUPS=$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l)
    if [ "$IOMMU_GROUPS" -gt 0 ]; then
        log_success "IOMMU is enabled with ${IOMMU_GROUPS} groups"
        USE_VFIO=true
    else
        log_warn "IOMMU groups not found. Check BIOS settings (VT-d/AMD-Vi)"
        log_warn "Will use uio_pci_generic instead (less secure)"
        USE_VFIO=false
    fi
else
    log_warn "IOMMU not available, will use uio_pci_generic"
    USE_VFIO=false
fi

###############################################################################
# Step 3: Load appropriate driver
###############################################################################
if [ "$USE_VFIO" = true ]; then
    log_info "Loading vfio-pci driver (recommended for production)..."
    modprobe vfio-pci
    DPDK_DRIVER="vfio-pci"
else
    log_info "Loading uio_pci_generic driver..."
    modprobe uio
    modprobe uio_pci_generic
    DPDK_DRIVER="uio_pci_generic"
fi

log_success "Driver ${DPDK_DRIVER} loaded"

###############################################################################
# Interactive Interface Binding
###############################################################################
echo ""
echo "========================================"
echo "  Interface Binding Options"
echo "========================================"
echo ""
echo "Available network interfaces:"
echo ""

# List available interfaces with details
ip -o link show | grep -v "lo:" | while read line; do
    IFACE=$(echo $line | awk -F': ' '{print $2}')
    STATE=$(echo $line | grep -oP 'state \K\w+')
    MAC=$(echo $line | grep -oP 'link/ether \K[\w:]+')
    echo "  - $IFACE (MAC: $MAC, State: $STATE)"
done

echo ""
echo "PCI devices that can be bound to DPDK:"
python3 ${DPDK_DEVBIND} --status-dev net | grep -E "^[0-9a-f]" | head -10

echo ""
log_warn "IMPORTANT: Do NOT bind your management interface!"
log_warn "Binding an interface will make it unavailable to Linux kernel."
echo ""

###############################################################################
# Helper functions for binding
###############################################################################
bind_interface() {
    local PCI_ADDR=$1
    local DRIVER=$2

    log_info "Binding ${PCI_ADDR} to ${DRIVER}..."

    # Unbind from current driver first
    python3 ${DPDK_DEVBIND} -u ${PCI_ADDR} 2>/dev/null || true

    # Bind to DPDK driver
    python3 ${DPDK_DEVBIND} -b ${DRIVER} ${PCI_ADDR}

    log_success "Interface ${PCI_ADDR} bound to ${DRIVER}"
}

unbind_interface() {
    local PCI_ADDR=$1
    local KERNEL_DRIVER=$2

    log_info "Unbinding ${PCI_ADDR} and restoring to ${KERNEL_DRIVER}..."
    python3 ${DPDK_DEVBIND} -u ${PCI_ADDR} 2>/dev/null || true
    python3 ${DPDK_DEVBIND} -b ${KERNEL_DRIVER} ${PCI_ADDR}
    log_success "Interface ${PCI_ADDR} restored to kernel driver"
}

###############################################################################
# Example: Bind specific interface (commented out for safety)
###############################################################################
# Uncomment and modify to bind your interface:
#
# Example 1: Bind by PCI address
# bind_interface "0000:02:00.0" "${DPDK_DRIVER}"
#
# Example 2: Bind by interface name (converts to PCI address)
# IFACE="eth1"
# PCI_ADDR=$(ethtool -i $IFACE 2>/dev/null | grep bus-info | awk '{print $2}')
# if [ -n "$PCI_ADDR" ]; then
#     bind_interface "$PCI_ADDR" "${DPDK_DRIVER}"
# fi

###############################################################################
# Create bind/unbind helper scripts
###############################################################################
log_info "Creating helper scripts..."

# Create bind script
cat > /usr/local/bin/dpdk-bind-nic << EOF
#!/bin/bash
# Bind a NIC to DPDK driver
# Usage: dpdk-bind-nic <pci-address> [driver]

if [ -z "\$1" ]; then
    echo "Usage: dpdk-bind-nic <pci-address> [driver]"
    echo "  driver defaults to: ${DPDK_DRIVER}"
    echo ""
    echo "Example: dpdk-bind-nic 0000:02:00.0"
    exit 1
fi

DRIVER=\${2:-${DPDK_DRIVER}}
modprobe \$DRIVER 2>/dev/null
python3 ${DPDK_DEVBIND} -u \$1 2>/dev/null
python3 ${DPDK_DEVBIND} -b \$DRIVER \$1
echo "Bound \$1 to \$DRIVER"
EOF
chmod +x /usr/local/bin/dpdk-bind-nic

# Create unbind script
cat > /usr/local/bin/dpdk-unbind-nic << 'EOF'
#!/bin/bash
# Unbind a NIC from DPDK and restore to kernel driver
# Usage: dpdk-unbind-nic <pci-address> [kernel-driver]

if [ -z "$1" ]; then
    echo "Usage: dpdk-unbind-nic <pci-address> [kernel-driver]"
    echo "  kernel-driver defaults to: ixgbe, i40e, or e1000"
    exit 1
fi

DPDK_DEVBIND=$(which dpdk-devbind.py 2>/dev/null || echo "/usr/local/bin/dpdk-devbind.py")
DRIVER=${2:-$(lspci -s $1 -v 2>/dev/null | grep "Kernel modules:" | awk '{print $3}')}

if [ -z "$DRIVER" ]; then
    echo "Could not determine kernel driver, please specify"
    exit 1
fi

python3 $DPDK_DEVBIND -u $1 2>/dev/null
python3 $DPDK_DEVBIND -b $DRIVER $1
echo "Unbound $1 and restored to $DRIVER"
EOF
chmod +x /usr/local/bin/dpdk-unbind-nic

# Create status script
cat > /usr/local/bin/dpdk-nic-status << EOF
#!/bin/bash
# Show DPDK NIC status
python3 ${DPDK_DEVBIND} --status-dev net
EOF
chmod +x /usr/local/bin/dpdk-nic-status

log_success "Helper scripts created in /usr/local/bin/"

###############################################################################
# Final Status
###############################################################################
echo ""
echo "============================================================"
echo "  Interface Binding Setup Complete!"
echo "============================================================"
echo ""
echo "Helper commands available:"
echo "  dpdk-nic-status        - Show all NIC status"
echo "  dpdk-bind-nic <pci>    - Bind NIC to DPDK driver"
echo "  dpdk-unbind-nic <pci>  - Restore NIC to kernel driver"
echo ""
echo "To bind an interface to DPDK:"
echo "  sudo dpdk-bind-nic 0000:XX:00.0"
echo ""
echo "Current status:"
python3 ${DPDK_DEVBIND} --status-dev net
echo ""
echo "Next: Run 05-sample-app.sh to test DPDK"
echo "============================================================"
