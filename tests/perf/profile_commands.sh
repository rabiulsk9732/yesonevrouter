#!/bin/bash
#
# YESRouter Profiling Commands Reference
# Run these on the VBNG host (172.16.17.3)
#

YESPID=$(pgrep -x yesrouter)

cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║           YESRouter Profiling Commands                       ║
╚══════════════════════════════════════════════════════════════╝

=== 1. CPU Profiling with perf ===

# Record CPU samples for 60 seconds (run as root)
sudo perf record -F 99 -g -p $YESPID -- sleep 60

# Generate flamegraph-ready output
sudo perf script > perf.script
# Then use flamegraph.pl to generate SVG

# Quick report
sudo perf report --stdio --sort=dso,symbol | head -50

# Top functions by CPU
sudo perf top -p $YESPID

=== 2. Lock Contention Analysis ===

# Record lock events
sudo perf record -e 'sched:sched_switch' -g -p $YESPID -- sleep 30
sudo perf report

# Context switches
sudo perf stat -e context-switches,cpu-migrations -p $YESPID -- sleep 10

=== 3. Memory Profiling ===

# Memory map snapshot
pmap -x $YESPID

# Detailed memory regions
cat /proc/$YESPID/smaps | grep -E '^[0-9a-f]|Rss|Pss|Private'

# Watch RSS growth
watch -n1 "ps -p $YESPID -o rss,vsz,pmem"

# Hugepages usage
cat /proc/meminfo | grep -i huge
cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages

=== 4. DPDK-specific Monitoring ===

# Check DPDK ports (via CLI)
echo "show interfaces" | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock

# DPDK mempool stats (if exposed)
# Look for rte_mempool_dump() output in logs

# EAL memory
cat /var/run/dpdk/rte/config 2>/dev/null

=== 5. Network/Packet Stats ===

# Interface counters
cat /proc/net/dev

# Socket stats
ss -s

# UDP buffer usage (for RADIUS)
cat /proc/net/udp

=== 6. eBPF/bpftrace Examples ===

# Trace malloc calls (requires bpftrace)
sudo bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc { @bytes = hist(arg0); }'

# Trace context switches for yesrouter
sudo bpftrace -e 'tracepoint:sched:sched_switch /args->prev_pid == '$YESPID' || args->next_pid == '$YESPID'/ { @switches = count(); }'

# Function latency (if symbols available)
sudo bpftrace -e 'uprobe:/opt/yesonevrouter/build/yesrouter:pppoe_rx_packet { @start[tid] = nsecs; }
                  uretprobe:/opt/yesonevrouter/build/yesrouter:pppoe_rx_packet /@start[tid]/ { @latency = hist(nsecs - @start[tid]); delete(@start[tid]); }'

=== 7. System-wide Monitoring ===

# CPU per core
mpstat -P ALL 1

# Memory pressure
vmstat 1

# I/O wait
iostat -x 1

# IRQ distribution
watch -n1 "cat /proc/interrupts | head -20"

=== 8. Quick Health Check ===

# All-in-one status
echo "=== Process ===" && ps aux | grep yesrouter | grep -v grep
echo "=== Memory ===" && free -m
echo "=== CPU ===" && uptime
echo "=== Sessions ===" && echo "show pppoe sessions" | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null | wc -l

EOF

echo ""
echo "Current yesrouter PID: $YESPID"
echo ""
echo "Quick stats:"
ps -p $YESPID -o pid,ppid,%cpu,%mem,rss,vsz,nlwp,etime --no-headers 2>/dev/null || echo "Process not running"
