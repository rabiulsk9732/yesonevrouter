#!/bin/bash
#
# YESRouter Deploy Script
# Compiles, installs, and starts the service
#
# Usage: ./deploy.sh [options]
#   -c, --compile-only   Only compile, don't install/restart
#   -r, --restart-only   Only restart service (no compile)
#   -s, --status         Show service status
#   -l, --logs           Show logs
#

set -e

# Configuration
REMOTE_HOST="ubuntu@172.16.17.3"
REMOTE_BUILD_DIR="/tmp/yesonevrouter_new"
INSTALL_DIR="/opt/yesonevrouter"
CONFIG_DIR="/etc/yesrouter"
SERVICE_NAME="yesrouter"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Sync source to remote
sync_source() {
    log_info "Syncing source to $REMOTE_HOST..."
    rsync -avz --delete \
        --exclude='build' \
        --exclude='.git' \
        --exclude='*.o' \
        --exclude='*.a' \
        /root/yesonevrouter/ \
        ${REMOTE_HOST}:${REMOTE_BUILD_DIR}/ 2>&1 | tail -5
}

# Compile on remote
compile() {
    log_info "Compiling on $REMOTE_HOST..."
    ssh ${REMOTE_HOST} << 'COMPILE_EOF'
        cd /tmp/yesonevrouter_new
        mkdir -p build
        cd build
        cmake .. -DCMAKE_BUILD_TYPE=Release
        make -j$(nproc)
        if [ $? -eq 0 ]; then
            echo "BUILD SUCCESS"
        else
            echo "BUILD FAILED"
            exit 1
        fi
COMPILE_EOF
}

# Install binary and configs
install_files() {
    log_info "Installing files..."
    ssh ${REMOTE_HOST} << INSTALL_EOF
        # Stop service if running
        sudo systemctl stop ${SERVICE_NAME} 2>/dev/null || true
        sudo pkill -9 yesrouter 2>/dev/null || true
        sleep 2

        # Create directories
        sudo mkdir -p ${INSTALL_DIR}/build
        sudo mkdir -p ${CONFIG_DIR}
        sudo mkdir -p /var/lib/yesrouter
        sudo mkdir -p /var/log/yesrouter
        sudo mkdir -p /run/yesrouter
        sudo chmod 755 /var/log/yesrouter
        sudo chmod 755 /run/yesrouter

        # Copy binary
        sudo cp -f ${REMOTE_BUILD_DIR}/build/yesrouter ${INSTALL_DIR}/build/
        sudo chmod +x ${INSTALL_DIR}/build/yesrouter

        # Copy configs (don't overwrite if exist)
        sudo cp -n ${REMOTE_BUILD_DIR}/config/yesrouter.conf ${CONFIG_DIR}/ 2>/dev/null || true
        sudo cp -n ${REMOTE_BUILD_DIR}/config/startup.gate ${CONFIG_DIR}/ 2>/dev/null || true

        # Install systemd service
        sudo cp ${REMOTE_BUILD_DIR}/config/yesrouter.service /etc/systemd/system/
        sudo systemctl daemon-reload

        # Create symlink for easy access
        sudo ln -sf ${INSTALL_DIR}/build/yesrouter /usr/local/bin/yesrouter

        echo "Installation complete"
INSTALL_EOF
}

# Start/restart service
start_service() {
    log_info "Starting service..."
    ssh ${REMOTE_HOST} << 'START_EOF'
        # For now, run directly (not via systemd) for testing
        sudo pkill -9 yesrouter 2>/dev/null || true
        sleep 1

        # Use new config location
        CONFIG_FILE="/etc/yesrouter/yesrouter.conf"

        echo "Starting yesrouter with config: $CONFIG_FILE"
        sudo touch /var/log/yesrouter/yesrouter.log
        sudo chmod 666 /var/log/yesrouter/yesrouter.log
        sudo /opt/yesonevrouter/build/yesrouter \
            --config $CONFIG_FILE \
            -d > /var/log/yesrouter/yesrouter.log 2>&1 &

        sleep 3

        # Check if running
        if pgrep -x yesrouter > /dev/null; then
            echo "YESRouter started successfully (PID: $(pgrep -x yesrouter))"
        else
            echo "Failed to start YESRouter"
            tail -20 /var/log/yesrouter/yesrouter.log
            exit 1
        fi
START_EOF
}

# Show status
show_status() {
    log_info "Service status:"
    ssh ${REMOTE_HOST} << 'STATUS_EOF'
        echo "=== Process Status ==="
        ps aux | grep yesrouter | grep -v grep || echo "Not running"

        echo ""
        echo "=== CLI Test ==="
        echo "show version" | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null | head -20 || echo "CLI not available"
STATUS_EOF
}

# Show logs
show_logs() {
    log_info "Recent logs:"
    ssh ${REMOTE_HOST} "sudo tail -50 /var/log/yesrouter/yesrouter.log 2>/dev/null || echo 'No logs'"
}

# Test CLI
test_cli() {
    log_info "Testing CLI..."
    ssh ${REMOTE_HOST} << 'CLI_EOF'
        echo -e "enable\nshow version\nshow pppoe sessions\nshow interfaces brief\nexit" | \
            sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null
CLI_EOF
}

# Main
case "${1:-}" in
    -c|--compile-only)
        sync_source
        compile
        ;;
    -r|--restart-only)
        start_service
        show_status
        ;;
    -s|--status)
        show_status
        ;;
    -l|--logs)
        show_logs
        ;;
    -t|--test)
        test_cli
        ;;
    -h|--help)
        echo "Usage: $0 [options]"
        echo "  -c, --compile-only   Only compile, don't install/restart"
        echo "  -r, --restart-only   Only restart service (no compile)"
        echo "  -s, --status         Show service status"
        echo "  -l, --logs           Show logs"
        echo "  -t, --test           Test CLI commands"
        echo "  (no args)            Full deploy: sync, compile, install, start"
        ;;
    *)
        # Full deploy
        sync_source
        compile
        install_files
        start_service
        echo ""
        show_status
        echo ""
        log_info "Deploy complete! Test with: ./deploy.sh -t"
        ;;
esac
