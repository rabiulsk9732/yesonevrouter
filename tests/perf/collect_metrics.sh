#!/bin/bash
#
# YESRouter Metrics Collector
# Collects CPU, memory, DPDK stats in real-time
#
# Usage: ./collect_metrics.sh [duration_sec] [output_dir]
#

DURATION=${1:-60}
OUTPUT_DIR=${2:-/tmp/metrics}
VBNG_HOST="ubuntu@172.16.17.3"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "${OUTPUT_DIR}"

echo "Collecting metrics for ${DURATION}s..."

#=============================================================================
# CPU & Memory (1-second intervals)
#=============================================================================
collect_cpu_mem() {
    ssh ${VBNG_HOST} << EOF > "${OUTPUT_DIR}/cpu_mem_${TIMESTAMP}.csv"
YESPID=\$(pgrep -x yesrouter)
echo "timestamp,cpu_percent,mem_percent,rss_kb,vsz_kb,threads"
for i in \$(seq 1 ${DURATION}); do
    TS=\$(date +%s)
    STATS=\$(ps -p \$YESPID -o %cpu,%mem,rss,vsz,nlwp --no-headers 2>/dev/null | tr -s ' ' ',')
    echo "\${TS},\${STATS}"
    sleep 1
done
EOF
}

#=============================================================================
# Per-core CPU usage
#=============================================================================
collect_per_core() {
    ssh ${VBNG_HOST} << EOF > "${OUTPUT_DIR}/per_core_${TIMESTAMP}.csv"
echo "timestamp,core,user,nice,system,idle,iowait,irq,softirq"
for i in \$(seq 1 ${DURATION}); do
    TS=\$(date +%s)
    grep '^cpu[0-9]' /proc/stat | while read line; do
        CORE=\$(echo \$line | awk '{print \$1}')
        USER=\$(echo \$line | awk '{print \$2}')
        NICE=\$(echo \$line | awk '{print \$3}')
        SYS=\$(echo \$line | awk '{print \$4}')
        IDLE=\$(echo \$line | awk '{print \$5}')
        IOWAIT=\$(echo \$line | awk '{print \$6}')
        IRQ=\$(echo \$line | awk '{print \$7}')
        SOFTIRQ=\$(echo \$line | awk '{print \$8}')
        echo "\${TS},\${CORE},\${USER},\${NICE},\${SYS},\${IDLE},\${IOWAIT},\${IRQ},\${SOFTIRQ}"
    done
    sleep 1
done
EOF
}

#=============================================================================
# PPPoE session stats
#=============================================================================
collect_pppoe_stats() {
    ssh ${VBNG_HOST} << EOF > "${OUTPUT_DIR}/pppoe_${TIMESTAMP}.log"
for i in \$(seq 1 \$((${DURATION} / 5))); do
    echo "=== \$(date) ==="
    echo "show pppoe sessions" | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null | head -20
    echo "show pppoe statistics" | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null
    sleep 5
done
EOF
}

#=============================================================================
# Memory details
#=============================================================================
collect_memory_details() {
    ssh ${VBNG_HOST} << EOF > "${OUTPUT_DIR}/memory_${TIMESTAMP}.log"
YESPID=\$(pgrep -x yesrouter)
echo "=== Memory Map ==="
pmap -x \$YESPID 2>/dev/null | tail -20

echo ""
echo "=== Hugepages ==="
cat /proc/meminfo | grep -i huge

echo ""
echo "=== DPDK Mempool (if available) ==="
cat /var/run/dpdk/rte/config 2>/dev/null | head -50 || echo "N/A"
EOF
}

#=============================================================================
# Network stats
#=============================================================================
collect_network_stats() {
    ssh ${VBNG_HOST} << EOF > "${OUTPUT_DIR}/network_${TIMESTAMP}.csv"
echo "timestamp,rx_packets,tx_packets,rx_bytes,tx_bytes,rx_errors,tx_errors"
for i in \$(seq 1 ${DURATION}); do
    TS=\$(date +%s)
    # Get stats from /proc/net/dev for DPDK-bound interface (may be empty)
    STATS=\$(cat /proc/net/dev | grep -E 'eth|ens' | head -1 | awk '{print \$2","\$3","\$10","\$11","\$4","\$12}')
    echo "\${TS},\${STATS}"
    sleep 1
done
EOF
}

#=============================================================================
# Run all collectors in parallel
#=============================================================================
echo "Starting collectors..."

collect_cpu_mem &
PID1=$!

collect_per_core &
PID2=$!

collect_pppoe_stats &
PID3=$!

collect_network_stats &
PID4=$!

# Wait for completion
wait $PID1 $PID2 $PID3 $PID4

# Collect memory details (one-shot)
collect_memory_details

echo ""
echo "Metrics collected to: ${OUTPUT_DIR}/"
ls -la "${OUTPUT_DIR}/"
