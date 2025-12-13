#!/bin/bash
###############################################################################
# DPDK Production Environment Setup - Step 2: Hugepages Configuration
# Critical for DPDK performance - allocates large memory pages
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
echo "  DPDK Production - Hugepages Configuration"
echo "============================================================"
echo ""

###############################################################################
# Configuration - Adjust these values based on your system
###############################################################################
# Number of 2MB hugepages (default: 2048 = 4GB)
# Adjust based on available memory and application needs
HUGEPAGES_2MB=${HUGEPAGES_2MB:-2048}

# Number of 1GB hugepages (for high-performance scenarios)
HUGEPAGES_1GB=${HUGEPAGES_1GB:-0}

# NUMA node configuration (set to -1 for non-NUMA systems)
NUMA_NODE=${NUMA_NODE:-0}

###############################################################################
# Step 1: Check current hugepage status
###############################################################################
log_info "Current hugepage status:"
cat /proc/meminfo | grep -i huge
echo ""

###############################################################################
# Step 2: Configure 2MB Hugepages (runtime)
###############################################################################
log_info "Configuring 2MB hugepages..."

# Check if NUMA is available
if [ -d /sys/devices/system/node/node0 ]; then
    log_info "NUMA detected, configuring per-node..."

    # Get number of NUMA nodes
    NUMA_NODES=$(ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l)
    PAGES_PER_NODE=$((HUGEPAGES_2MB / NUMA_NODES))

    for node_dir in /sys/devices/system/node/node*; do
        node=$(basename $node_dir)
        echo $PAGES_PER_NODE > /sys/devices/system/node/${node}/hugepages/hugepages-2048kB/nr_hugepages
        log_info "  ${node}: ${PAGES_PER_NODE} hugepages"
    done
else
    log_info "Non-NUMA system, configuring globally..."
    echo $HUGEPAGES_2MB > /proc/sys/vm/nr_hugepages
fi

###############################################################################
# Step 3: Mount hugetlbfs
###############################################################################
log_info "Setting up hugetlbfs mount..."

# Create mount point
mkdir -p /dev/hugepages
mkdir -p /mnt/huge

# Mount hugetlbfs for 2MB pages
if ! mountpoint -q /dev/hugepages; then
    mount -t hugetlbfs nodev /dev/hugepages
fi

if ! mountpoint -q /mnt/huge; then
    mount -t hugetlbfs nodev /mnt/huge -o pagesize=2M
fi

# Set permissions
chmod 777 /dev/hugepages
chmod 777 /mnt/huge

log_success "Hugetlbfs mounted"

###############################################################################
# Step 4: Make configuration persistent
###############################################################################
log_info "Making hugepage configuration persistent..."

# Add to /etc/fstab if not already present
FSTAB_ENTRY_1="nodev /dev/hugepages hugetlbfs defaults 0 0"
FSTAB_ENTRY_2="nodev /mnt/huge hugetlbfs pagesize=2M 0 0"

if ! grep -q "/dev/hugepages" /etc/fstab; then
    echo "$FSTAB_ENTRY_1" >> /etc/fstab
    log_info "Added /dev/hugepages to /etc/fstab"
fi

if ! grep -q "/mnt/huge" /etc/fstab; then
    echo "$FSTAB_ENTRY_2" >> /etc/fstab
    log_info "Added /mnt/huge to /etc/fstab"
fi

# Configure sysctl for persistent hugepages
cat > /etc/sysctl.d/99-dpdk-hugepages.conf << EOF
# DPDK Hugepage Configuration
vm.nr_hugepages = ${HUGEPAGES_2MB}
vm.hugetlb_shm_group = 0

# Memory locking (for DPDK)
vm.max_map_count = 262144

# Network optimizations for DPDK
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 134217728
net.core.wmem_default = 134217728
net.core.optmem_max = 134217728
net.core.netdev_max_backlog = 250000
EOF

sysctl -p /etc/sysctl.d/99-dpdk-hugepages.conf 2>/dev/null || true

log_success "Persistent configuration applied"

###############################################################################
# Step 5: Configure GRUB for boot-time hugepages (recommended for production)
###############################################################################
log_info "Configuring GRUB for boot-time hugepages..."

GRUB_CMDLINE="default_hugepagesz=2M hugepagesz=2M hugepages=${HUGEPAGES_2MB} iommu=pt"

# Backup original grub config
cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)

# Check if hugepage parameters already exist
if ! grep -q "hugepages=" /etc/default/grub; then
    # Add hugepage parameters to GRUB_CMDLINE_LINUX_DEFAULT
    sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_CMDLINE} /" /etc/default/grub

    log_info "Updated GRUB configuration"
    log_warn "Run 'update-grub' and reboot for boot-time hugepages"
else
    log_info "Hugepage parameters already in GRUB configuration"
fi

###############################################################################
# Step 6: Verify Configuration
###############################################################################
echo ""
log_info "Verifying hugepage configuration..."
echo "----------------------------------------"
echo "Hugepages Total: $(cat /proc/meminfo | grep HugePages_Total | awk '{print $2}')"
echo "Hugepages Free:  $(cat /proc/meminfo | grep HugePages_Free | awk '{print $2}')"
echo "Hugepage Size:   $(cat /proc/meminfo | grep Hugepagesize | awk '{print $2, $3}')"
echo "----------------------------------------"

# Show mount status
log_info "Mount status:"
mount | grep huge

echo ""
echo "============================================================"
echo "  Hugepage configuration complete!"
echo ""
echo "  For production, reboot after running:"
echo "    sudo update-grub"
echo ""
echo "  Next: Run 03-install-dpdk.sh"
echo "============================================================"
