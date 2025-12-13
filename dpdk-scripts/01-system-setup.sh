#!/bin/bash
###############################################################################
# DPDK Production Environment Setup - Step 1: System Preparation
# For Ubuntu 22.04 LTS
# DPDK Version: 23.11 LTS (Long Term Support - maintained until Dec 2026)
###############################################################################

set -e  # Exit on error
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (sudo)"
   exit 1
fi

echo "============================================================"
echo "  DPDK Production Environment - System Preparation"
echo "  Target: Ubuntu 22.04 LTS"
echo "  DPDK Version: 23.11 LTS"
echo "============================================================"
echo ""

###############################################################################
# Step 1: System Update and Upgrade
###############################################################################
log_info "Updating package lists..."
apt-get update -y

log_info "Performing full system upgrade..."
apt-get upgrade -y

log_info "Performing distribution upgrade..."
apt-get dist-upgrade -y

log_info "Installing essential build tools..."
apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    ninja-build \
    pkg-config \
    automake \
    autoconf \
    libtool \
    git \
    wget \
    curl \
    unzip

log_success "System update and build tools installed"

###############################################################################
# Step 2: Install DPDK Dependencies
###############################################################################
log_info "Installing DPDK dependencies..."

# Core dependencies
apt-get install -y \
    libnuma-dev \
    libpcap-dev \
    libelf-dev \
    libjansson-dev \
    libbsd-dev \
    libcrypto++-dev \
    libssl-dev \
    zlib1g-dev

# Python and Meson (DPDK build system)
apt-get install -y \
    python3 \
    python3-pip \
    python3-pyelftools \
    python3-sphinx \
    python3-setuptools

# Install Meson via pip (need version >= 0.53.2 for DPDK)
pip3 install meson ninja pyelftools

# Network and hardware dependencies
apt-get install -y \
    libibverbs-dev \
    libmlx5-1 \
    libmlx4-1 \
    rdma-core \
    ibverbs-providers

# Additional optional but recommended
apt-get install -y \
    libisal-dev \
    libipsec-mb-dev 2>/dev/null || log_warn "libipsec-mb-dev not available, skipping..."

log_success "DPDK dependencies installed"

###############################################################################
# Step 3: Kernel Headers and Modules
###############################################################################
log_info "Installing kernel headers and modules..."

apt-get install -y \
    linux-headers-$(uname -r) \
    linux-modules-extra-$(uname -r) 2>/dev/null || true

log_success "Kernel headers installed"

###############################################################################
# Step 4: Clean up
###############################################################################
log_info "Cleaning up..."
apt-get autoremove -y
apt-get autoclean -y

log_success "System preparation complete!"

echo ""
echo "============================================================"
echo "  System preparation completed successfully!"
echo "  Next: Run 02-configure-hugepages.sh"
echo "============================================================"
