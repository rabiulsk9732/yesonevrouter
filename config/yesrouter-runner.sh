#!/bin/bash
#
# YESRouter vBNG - Industry-Grade Startup Script (Bison-style)
# This script prepares the system and starts yesrouter
#

set -e

# Source environment config (Bison-style)
YESROUTER_ENV="/etc/yesrouter/yesrouter.env"
if [ -f "$YESROUTER_ENV" ]; then
    source "$YESROUTER_ENV"
fi

YESROUTER_BIN="/usr/local/bin/yesrouter"
YESROUTER_CONF="/etc/yesrouter/yesrouter.conf"
DPDK_RUNTIME_DIR="/var/run/dpdk"
HUGEPAGE_MOUNT="/dev/hugepages"
MIN_HUGEPAGES=${yr_hugepages:-2048}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
}

# Step 1: Clean up stale DPDK runtime files
cleanup_dpdk() {
    log "Cleaning up stale DPDK runtime files..."
    rm -rf ${DPDK_RUNTIME_DIR}/* 2>/dev/null || true
    rm -f /var/run/.rte_config 2>/dev/null || true
    rm -f /var/run/.rte_hugepage_info 2>/dev/null || true
}

# Step 2: Configure hugepages
setup_hugepages() {
    log "Configuring hugepages..."

    # Check current hugepages
    current=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo 0)

    if [ "$current" -lt "$MIN_HUGEPAGES" ]; then
        log "Allocating $MIN_HUGEPAGES hugepages (current: $current)..."
        echo $MIN_HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

        # Verify allocation
        allocated=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
        if [ "$allocated" -lt "$MIN_HUGEPAGES" ]; then
            error "Failed to allocate hugepages. Got $allocated, need $MIN_HUGEPAGES"
            error "Try: echo 'vm.nr_hugepages=$MIN_HUGEPAGES' >> /etc/sysctl.conf && sysctl -p"
            exit 1
        fi
    fi

    # Mount hugetlbfs if not mounted
    if ! mountpoint -q "$HUGEPAGE_MOUNT" 2>/dev/null; then
        log "Mounting hugetlbfs..."
        mkdir -p "$HUGEPAGE_MOUNT"
        mount -t hugetlbfs nodev "$HUGEPAGE_MOUNT" || true
    fi

    log "Hugepages ready: $(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages) x 2MB"
}

# Step 3: Load required kernel modules
load_modules() {
    log "Loading kernel modules..."
    modprobe uio_pci_generic 2>/dev/null || true
    modprobe vfio-pci 2>/dev/null || true
}

# Step 4: Bind NICs to DPDK (optional - can be done externally)
bind_nics() {
    # This is optional - NICs should be pre-bound or configured in startup
    if [ -f /etc/yesrouter/dpdk-bind.conf ]; then
        log "Binding NICs to DPDK driver..."
        while read -r pci_addr driver; do
            [ -z "$pci_addr" ] && continue
            [[ "$pci_addr" =~ ^# ]] && continue
            dpdk-devbind.py -b "$driver" "$pci_addr" 2>/dev/null || true
        done < /etc/yesrouter/dpdk-bind.conf
    fi
}

# Step 5: Create runtime directories
create_dirs() {
    log "Creating runtime directories..."
    mkdir -p /var/run/yesrouter
    mkdir -p /var/log/yesrouter
    mkdir -p ${DPDK_RUNTIME_DIR}
}

# Step 6: Verify binary exists
verify_binary() {
    if [ ! -x "$YESROUTER_BIN" ]; then
        error "Binary not found or not executable: $YESROUTER_BIN"
        exit 1
    fi
}

# Main execution
main() {
    log "=========================================="
    log "YESRouter vBNG - Starting"
    log "=========================================="

    cleanup_dpdk
    setup_hugepages
    load_modules
    bind_nics
    create_dirs
    verify_binary

    log "Pre-flight checks complete. Starting yesrouter..."

    # Execute yesrouter with proper signal handling
    exec "$YESROUTER_BIN" --daemon "$@"
}

main "$@"
