#!/bin/bash
#
# YESRouter Offline Installer
# Installs DPDK, kernel config, and all dependencies
#

set -e

# Version Configuration
DPDK_VERSION="23.11"
YESROUTER_VERSION="1.0.0"
MIN_KERNEL="5.4.0"

# Directories
INSTALL_DIR="/opt/yesrouter"
DPDK_DIR="/opt/dpdk"
CONFIG_DIR="/etc/yesrouter"
LOG_DIR="/var/log/yesrouter"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

#
# Check system requirements
#
check_requirements() {
    log_info "Checking system requirements..."

    # Check root
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi

    # Check kernel version
    KERNEL_VER=$(uname -r | cut -d'-' -f1)
    if [ "$(printf '%s\n' "$MIN_KERNEL" "$KERNEL_VER" | sort -V | head -n1)" != "$MIN_KERNEL" ]; then
        log_error "Kernel $KERNEL_VER is too old. Minimum: $MIN_KERNEL"
        exit 1
    fi
    log_info "Kernel: $KERNEL_VER (OK)"

    # Check CPU
    CORES=$(nproc)
    if [ "$CORES" -lt 2 ]; then
        log_warn "Only $CORES CPU cores detected. Recommended: 4+"
    fi
    log_info "CPU cores: $CORES"

    # Check memory
    MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$MEM_GB" -lt 4 ]; then
        log_warn "Only ${MEM_GB}GB RAM. Recommended: 8GB+"
    fi
    log_info "Memory: ${MEM_GB}GB"

    # Check hugepages
    HUGE_TOTAL=$(grep HugePages_Total /proc/meminfo | awk '{print $2}')
    if [ "$HUGE_TOTAL" -lt 1024 ]; then
        log_warn "Hugepages: $HUGE_TOTAL (will configure)"
    else
        log_info "Hugepages: $HUGE_TOTAL (OK)"
    fi
}

#
# Install dependencies (offline mode uses local debs)
#
install_dependencies() {
    log_info "Installing dependencies..."

    DEPS="build-essential meson ninja-build python3-pyelftools libnuma-dev pkg-config"

    # Check if we have local packages
    if [ -d "$SCRIPT_DIR/packages" ]; then
        log_info "Installing from local packages (offline mode)"
        dpkg -i $SCRIPT_DIR/packages/*.deb 2>/dev/null || true
        apt-get -f install -y
    else
        log_info "Installing from apt (online mode)"
        apt-get update
        apt-get install -y $DEPS
    fi
}

#
# Configure kernel for DPDK
#
configure_kernel() {
    log_info "Configuring kernel for DPDK..."

    # GRUB configuration
    GRUB_FILE="/etc/default/grub"
    GRUB_OPTS="intel_iommu=on iommu=pt default_hugepagesz=2M hugepagesz=2M hugepages=2048"

    if ! grep -q "hugepages=" "$GRUB_FILE"; then
        log_info "Updating GRUB configuration..."

        # Backup
        cp "$GRUB_FILE" "${GRUB_FILE}.bak"

        # Add kernel options
        if grep -q "GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_FILE"; then
            sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_OPTS /" "$GRUB_FILE"
        else
            echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_OPTS\"" >> "$GRUB_FILE"
        fi

        update-grub
        log_warn "GRUB updated. Reboot required for hugepages."
    else
        log_info "GRUB already configured"
    fi

    # Load VFIO modules
    modprobe vfio-pci 2>/dev/null || true
    echo "vfio-pci" >> /etc/modules-load.d/dpdk.conf 2>/dev/null || true

    # Enable no-IOMMU mode for VMs
    echo "options vfio enable_unsafe_noiommu_mode=1" > /etc/modprobe.d/vfio.conf

    # Sysctl tuning
    cat > /etc/sysctl.d/99-yesrouter.conf << 'EOF'
# YESRouter DPDK tuning
vm.nr_hugepages = 2048
vm.hugetlb_shm_group = 0
kernel.shmmax = 17179869184
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 134217728
net.core.wmem_default = 134217728
net.core.netdev_max_backlog = 250000
EOF
    sysctl -p /etc/sysctl.d/99-yesrouter.conf 2>/dev/null || true

    # Mount hugepages
    mkdir -p /dev/hugepages
    if ! mount | grep -q hugepages; then
        mount -t hugetlbfs nodev /dev/hugepages 2>/dev/null || true
    fi

    # Add to fstab
    if ! grep -q hugetlbfs /etc/fstab; then
        echo "nodev /dev/hugepages hugetlbfs defaults 0 0" >> /etc/fstab
    fi
}

#
# Install DPDK
#
install_dpdk() {
    log_info "Installing DPDK $DPDK_VERSION..."

    mkdir -p "$DPDK_DIR"

    # Check if DPDK source is bundled
    if [ -f "$SCRIPT_DIR/dpdk-${DPDK_VERSION}.tar.xz" ]; then
        log_info "Using bundled DPDK source"
        tar -xf "$SCRIPT_DIR/dpdk-${DPDK_VERSION}.tar.xz" -C /tmp/
    elif [ -d "/tmp/dpdk-${DPDK_VERSION}" ]; then
        log_info "Using existing DPDK source"
    else
        log_info "Downloading DPDK $DPDK_VERSION..."
        wget -q "https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz" -O /tmp/dpdk.tar.xz
        tar -xf /tmp/dpdk.tar.xz -C /tmp/
    fi

    cd /tmp/dpdk-${DPDK_VERSION}

    # Build DPDK
    log_info "Building DPDK (this may take a few minutes)..."
    meson setup build --prefix="$DPDK_DIR" -Dexamples='' -Dtests=false
    ninja -C build
    ninja -C build install

    # Set up pkg-config
    echo "$DPDK_DIR/lib/x86_64-linux-gnu/pkgconfig" > /etc/ld.so.conf.d/dpdk.conf
    ldconfig

    # Create version file
    echo "DPDK_VERSION=$DPDK_VERSION" > "$DPDK_DIR/version"
    echo "INSTALL_DATE=$(date -Iseconds)" >> "$DPDK_DIR/version"
    echo "KERNEL=$(uname -r)" >> "$DPDK_DIR/version"

    log_info "DPDK $DPDK_VERSION installed to $DPDK_DIR"
}

#
# Install YESRouter
#
install_yesrouter() {
    log_info "Installing YESRouter..."

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"

    # Copy binary
    if [ -f "$SCRIPT_DIR/../build/yesrouter" ]; then
        cp "$SCRIPT_DIR/../build/yesrouter" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/yesrouter"
    fi

    # Copy utilities
    cp "$SCRIPT_DIR/../yesrouter-dpdk" /usr/local/bin/ 2>/dev/null || true
    chmod +x /usr/local/bin/yesrouter-dpdk 2>/dev/null || true

    # Copy default config if not exists
    if [ ! -f "$CONFIG_DIR/yesrouter.env" ]; then
        cat > "$CONFIG_DIR/yesrouter.env" << 'EOF'
#
# YESRouter - Simplified Environment
#

# ===================
# CORES & MEMORY
# ===================
MAIN_LCORE=0
WORKER_LCORES=1
MEMORY_MB=2048

# ===================
# PORTS (PCI addresses)
# ===================
PCI=(
    # Add your NIC PCI addresses here
    # Example: 0000:06:00.0  # WAN
    # Example: 0000:06:00.1  # LAN
)

# ===================
# QUEUES
# ===================
RX_QUEUES=1
TX_QUEUES=1

# ===================
# LOGGING
# ===================
LOG_LEVEL=info
EOF
    fi

    # Install systemd service
    cat > /etc/systemd/system/yesrouter.service << EOF
[Unit]
Description=YESRouter vBNG
After=network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStartPre=/bin/rm -rf /var/run/dpdk/vbng
ExecStartPre=/bin/mkdir -p /run/yesrouter
ExecStart=$INSTALL_DIR/yesrouter --config $CONFIG_DIR/startup.json
Restart=on-failure
RestartSec=3
LimitMEMLOCK=infinity
LimitNOFILE=1048576
Environment="HOME=/root"
EnvironmentFile=$CONFIG_DIR/yesrouter.env

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable yesrouter

    # Create version file
    cat > "$INSTALL_DIR/version" << EOF
YESROUTER_VERSION=$YESROUTER_VERSION
DPDK_VERSION=$DPDK_VERSION
INSTALL_DATE=$(date -Iseconds)
KERNEL=$(uname -r)
EOF

    log_info "YESRouter installed to $INSTALL_DIR"
}

#
# Show status
#
show_status() {
    echo ""
    echo "=========================================="
    echo "  YESRouter Installation Complete"
    echo "=========================================="
    echo ""
    echo "Versions:"
    echo "  YESRouter: $YESROUTER_VERSION"
    echo "  DPDK:      $DPDK_VERSION"
    echo "  Kernel:    $(uname -r)"
    echo ""
    echo "Directories:"
    echo "  Install:   $INSTALL_DIR"
    echo "  Config:    $CONFIG_DIR"
    echo "  DPDK:      $DPDK_DIR"
    echo ""
    echo "Next steps:"
    echo "  1. Edit $CONFIG_DIR/yesrouter.env"
    echo "     - Add your NIC PCI addresses to PCI=()"
    echo "  2. Run: yesrouter-dpdk status"
    echo "  3. Run: systemctl start yesrouter"
    echo ""

    # Check if reboot needed
    HUGE_TOTAL=$(grep HugePages_Total /proc/meminfo | awk '{print $2}')
    if [ "$HUGE_TOTAL" -lt 1024 ]; then
        echo -e "${YELLOW}NOTE: Reboot required for hugepages to take effect${NC}"
    fi
}

#
# Main
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

case "${1:-install}" in
    install)
        check_requirements
        install_dependencies
        configure_kernel
        install_dpdk
        install_yesrouter
        show_status
        ;;
    dpdk-only)
        check_requirements
        install_dependencies
        install_dpdk
        ;;
    kernel-only)
        configure_kernel
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 [install|dpdk-only|kernel-only|status]"
        exit 1
        ;;
esac
