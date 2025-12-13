#!/bin/bash
#
# YESRouter System Tuning Script
# Apply before running performance tests
#
# Usage: ./apply_tuning.sh [target_sessions]
#

TARGET=${1:-10000}
VBNG_HOST="ubuntu@172.16.17.3"

echo "Applying system tuning for ${TARGET} sessions..."

ssh ${VBNG_HOST} << EOF
set -x

#=============================================================================
# Hugepages (2MB pages)
#=============================================================================
# Calculate required hugepages: ~2KB per session + base DPDK needs
HUGEPAGES=\$(( (${TARGET} * 2 / 2048) + 1024 ))
[ \$HUGEPAGES -lt 1024 ] && HUGEPAGES=1024
[ \$HUGEPAGES -gt 4096 ] && HUGEPAGES=4096

echo "Setting hugepages to \$HUGEPAGES"
sudo sysctl -w vm.nr_hugepages=\$HUGEPAGES
echo \$HUGEPAGES | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

#=============================================================================
# Network Buffers
#=============================================================================
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.core.wmem_max=268435456
sudo sysctl -w net.core.rmem_default=16777216
sudo sysctl -w net.core.wmem_default=16777216
sudo sysctl -w net.core.netdev_max_backlog=250000
sudo sysctl -w net.core.somaxconn=65535

# UDP buffers for RADIUS
sudo sysctl -w net.ipv4.udp_rmem_min=16384
sudo sysctl -w net.ipv4.udp_wmem_min=16384

#=============================================================================
# Memory Management
#=============================================================================
sudo sysctl -w vm.swappiness=10
sudo sysctl -w vm.dirty_ratio=10
sudo sysctl -w vm.dirty_background_ratio=5
sudo sysctl -w vm.overcommit_memory=1

#=============================================================================
# File Descriptors
#=============================================================================
sudo sysctl -w fs.file-max=2097152
sudo sysctl -w fs.nr_open=2097152

# Set ulimits for current session
ulimit -n 1048576 2>/dev/null || true
ulimit -l unlimited 2>/dev/null || true

#=============================================================================
# CPU Performance
#=============================================================================
# Disable CPU frequency scaling (if available)
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee \$cpu 2>/dev/null || true
done

# Disable turbo boost for consistent performance (optional)
# echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true

#=============================================================================
# IRQ Affinity (move IRQs away from DPDK cores)
#=============================================================================
# Assuming cores 1-3 are for DPDK, move IRQs to core 0
for irq in /proc/irq/*/smp_affinity; do
    echo 1 | sudo tee \$irq 2>/dev/null || true
done

#=============================================================================
# Disable Kernel Features that Interfere
#=============================================================================
sudo sysctl -w net.ipv4.tcp_timestamps=0
sudo sysctl -w net.ipv4.tcp_sack=0
sudo sysctl -w kernel.numa_balancing=0

# Disable transparent hugepages (can cause latency spikes)
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true

#=============================================================================
# Verify Settings
#=============================================================================
echo ""
echo "=== Verification ==="
echo "Hugepages: \$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
echo "Free hugepages: \$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages)"
echo "rmem_max: \$(sysctl -n net.core.rmem_max)"
echo "wmem_max: \$(sysctl -n net.core.wmem_max)"
echo "swappiness: \$(sysctl -n vm.swappiness)"
echo "file-max: \$(sysctl -n fs.file-max)"

echo ""
echo "Tuning complete!"
EOF

echo "Done."
