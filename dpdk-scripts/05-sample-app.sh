#!/bin/bash
# DPDK Sample Application - Creates a test program
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}/sample_app"
mkdir -p ${APP_DIR}

echo "Creating DPDK test application..."

# Create test script
cat > ${APP_DIR}/test_dpdk.sh << 'EOF'
#!/bin/bash
echo "Testing DPDK installation..."
if pkg-config --exists libdpdk; then
    echo "DPDK Version: $(pkg-config --modversion libdpdk)"
    echo "DPDK is installed correctly!"
else
    echo "DPDK not found"
    exit 1
fi
EOF
chmod +x ${APP_DIR}/test_dpdk.sh

echo "Test application created in ${APP_DIR}"
echo "Run: cd ${APP_DIR} && ./test_dpdk.sh"
