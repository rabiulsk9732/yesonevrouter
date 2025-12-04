#!/bin/bash
#
# YESRouter - Simple Launcher
# ONE command to start everything
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Clean up any previous instances
pkill -9 yesrouter 2>/dev/null || true
rm -f /var/run/dpdk/rte/config 2>/dev/null || true

# Check DPDK interfaces
DPDK_COUNT=$(./tools/dpdk-devbind.py -s | grep -c "drv=vfio-pci")
if [ "$DPDK_COUNT" -lt 2 ]; then
    echo -e "${YELLOW}Setting up DPDK interfaces...${NC}"
    sudo ./tools/setup_dpdk.sh 0000:00:13.0 0000:00:14.0
    sleep 2
fi

# Parse startup.conf FIRST (before router starts)
if [ -f "config/startup.conf" ]; then
    source ./parse_startup_conf.sh
fi

# Setup DPDK devices BEFORE starting router
if [ -n "$DPDK_DEVS" ]; then
    echo -e "${BLUE}Setting up DPDK devices from startup.conf...${NC}"
    sudo ./tools/setup_dpdk.sh $DPDK_DEVS > /dev/null 2>&1
    echo -e "${GREEN}✓ DPDK configured${NC}"
fi

clear
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}       YESRouter vBNG${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ -n "$EXEC_FILE" ] && [ -f "$EXEC_FILE" ]; then
    echo -e "${GREEN}✓ Will execute: $EXEC_FILE${NC}"
    echo ""
fi

echo -e "${GREEN}✓ Starting router...${NC}"
echo ""

# Start router with piped input from exec file
if [ -n "$EXEC_FILE" ] && [ -f "$EXEC_FILE" ]; then
    (
        # Wait for router to initialize
        sleep 4

        # Auto-login
        echo "admin"
        sleep 0.5
        echo "admin"
        sleep 1

        # Send commands from exec file
        while IFS= read -r cmd; do
            if [[ ! "$cmd" =~ ^# ]] && [ -n "$cmd" ]; then
                echo "$cmd"
                sleep 0.3
            fi
        done < "$EXEC_FILE"

        # Keep stdin open
        cat
    ) | ./build/yesrouter 2>/dev/null
else
    # No exec file, just start router
    ./build/yesrouter 2>/dev/null
fi
