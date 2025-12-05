#!/bin/bash
# NAT Load Test Runner
# Tests NAT performance with realistic session counts

set -e

echo "=========================================="
echo "NAT Load Test - MPPS Per Core"
echo "=========================================="
echo ""

# Default parameters
NUM_SESSIONS=${1:-10000}
PACKETS_PER_SESSION=${2:-1000}
DURATION=${3:-60}
THREADS=${4:-8}

echo "Configuration:"
echo "  Sessions: $NUM_SESSIONS"
echo "  Packets per session: $PACKETS_PER_SESSION"
echo "  Duration: $DURATION seconds"
echo "  Threads: $THREADS"
echo ""

# Check if binary exists
if [ ! -f "build/tools/nat_load_test" ]; then
    echo "Building NAT load test tool..."
    cd "$(dirname "$0")"
    mkdir -p build
    cd build
    cmake ..
    make nat_load_test -j$(nproc)
    cd ..
fi

# Run the test
echo "Starting load test..."
echo ""

./build/tools/nat_load_test $NUM_SESSIONS $PACKETS_PER_SESSION $DURATION $THREADS

echo ""
echo "Load test complete!"
