#!/bin/bash
###############################################################################
# DPDK Production Environment Setup - Step 3: Install DPDK 23.11 LTS
# Building from source for production with full optimization
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
echo "  DPDK Production - Installing DPDK 23.11 LTS"
echo "============================================================"
echo ""

###############################################################################
# Configuration
###############################################################################
DPDK_VERSION="23.11.2"  # Latest stable LTS release
DPDK_DIR="/opt/dpdk"
DPDK_BUILD="${DPDK_DIR}/build"
DPDK_INSTALL="/usr/local"
DPDK_TARBALL="dpdk-${DPDK_VERSION}.tar.xz"
DPDK_URL="https://fast.dpdk.org/rel/${DPDK_TARBALL}"

# Number of parallel jobs for compilation
JOBS=$(nproc)

###############################################################################
# Step 1: Download DPDK
###############################################################################
log_info "Creating DPDK directory..."
mkdir -p ${DPDK_DIR}
cd ${DPDK_DIR}

if [ -f "${DPDK_TARBALL}" ]; then
    log_info "DPDK tarball already exists, skipping download..."
else
    log_info "Downloading DPDK ${DPDK_VERSION}..."
    wget -q --show-progress ${DPDK_URL}
fi

###############################################################################
# Step 2: Extract DPDK
###############################################################################
log_info "Extracting DPDK..."
tar xf ${DPDK_TARBALL}
cd dpdk-stable-${DPDK_VERSION}

log_success "DPDK source extracted to ${DPDK_DIR}/dpdk-${DPDK_VERSION}"

###############################################################################
# Step 3: Configure DPDK with Meson
###############################################################################
log_info "Configuring DPDK build with Meson..."

# Production build configuration
# -Dbuildtype=release: Optimized build
# -Dprefix: Installation directory
# -Dmachine=native: Optimize for current CPU
# -Dmax_ethports=32: Maximum Ethernet ports
# -Dmax_lcores=128: Maximum logical cores
# -Ddisable_drivers: Disable unnecessary drivers (adjust as needed)

meson setup ${DPDK_BUILD} \
    --prefix=${DPDK_INSTALL} \
    -Dbuildtype=release \
    -Ddefault_library=shared \
    -Dmachine=native \
    -Dmax_ethports=32 \
    -Dmax_lcores=128 \
    -Dtests=false \
    -Dexamples=all \
    -Denable_kmods=true

log_success "DPDK configuration complete"

###############################################################################
# Step 4: Build DPDK
###############################################################################
log_info "Building DPDK with ${JOBS} parallel jobs..."
log_info "This may take several minutes..."

ninja -C ${DPDK_BUILD} -j${JOBS}

log_success "DPDK build complete"

###############################################################################
# Step 5: Install DPDK
###############################################################################
log_info "Installing DPDK to ${DPDK_INSTALL}..."

ninja -C ${DPDK_BUILD} install

# Update library cache
ldconfig

log_success "DPDK installed"

###############################################################################
# Step 6: Set up environment variables
###############################################################################
log_info "Setting up environment variables..."

cat > /etc/profile.d/dpdk.sh << 'EOF'
# DPDK Environment Variables
export RTE_SDK=/opt/dpdk/dpdk-stable-23.11.2
export RTE_TARGET=x86_64-native-linux-gcc
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
EOF

# Source immediately
source /etc/profile.d/dpdk.sh

log_success "Environment variables configured"

###############################################################################
# Step 7: Install DPDK kernel modules
###############################################################################
log_info "Loading DPDK kernel modules..."

# Load vfio-pci (preferred for production)
modprobe vfio-pci 2>/dev/null || log_warn "vfio-pci module not available"

# Load uio and uio_pci_generic (alternative)
modprobe uio 2>/dev/null || true
modprobe uio_pci_generic 2>/dev/null || log_warn "uio_pci_generic not available"

# Make modules load at boot
cat > /etc/modules-load.d/dpdk.conf << EOF
# DPDK Kernel Modules
vfio-pci
uio
uio_pci_generic
EOF

log_success "Kernel modules configured"

###############################################################################
# Step 8: Verify Installation
###############################################################################
echo ""
log_info "Verifying DPDK installation..."
echo "----------------------------------------"

# Check pkg-config
if pkg-config --exists libdpdk; then
    DPDK_INSTALLED_VERSION=$(pkg-config --modversion libdpdk)
    echo "DPDK Version: ${DPDK_INSTALLED_VERSION}"
    echo "DPDK Libs: $(pkg-config --libs libdpdk | head -c 60)..."
    echo "DPDK CFLAGS: $(pkg-config --cflags libdpdk | head -c 60)..."
else
    log_error "pkg-config cannot find libdpdk"
fi

# Check for key binaries
echo ""
echo "DPDK binaries:"
ls -la /usr/local/bin/dpdk-* 2>/dev/null | head -5 || echo "No DPDK binaries found in /usr/local/bin"

# Check libraries
echo ""
echo "DPDK libraries:"
ls -la /usr/local/lib/x86_64-linux-gnu/librte_*.so 2>/dev/null | head -5 || \
ls -la /usr/local/lib/librte_*.so 2>/dev/null | head -5 || echo "Libraries not found in expected location"

echo "----------------------------------------"

echo ""
echo "============================================================"
echo "  DPDK ${DPDK_VERSION} installation complete!"
echo ""
echo "  DPDK is installed at: ${DPDK_INSTALL}"
echo "  Source code at: ${DPDK_DIR}/dpdk-${DPDK_VERSION}"
echo ""
echo "  Next: Run 04-bind-interfaces.sh to bind NICs"
echo "============================================================"
