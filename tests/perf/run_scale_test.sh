#!/bin/bash
#
# YESRouter Scale Test Runner
# Usage: ./run_scale_test.sh <target_sessions> [ramp_sec] [hold_sec]
#
# Example: ./run_scale_test.sh 5000 60 180
#

set -e

# Configuration
VBNG_HOST="ubuntu@172.16.17.3"
BLASTER_HOST="ubuntu@172.16.17.2"
RESULTS_DIR="/root/yesonevrouter/tests/perf/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Defaults
TARGET_SESSIONS=${1:-1000}
RAMP_SEC=${2:-60}
HOLD_SEC=${3:-180}
RAMPDOWN_SEC=30
REPEAT_COUNT=3

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Create results directory
mkdir -p "${RESULTS_DIR}/${TIMESTAMP}"
RESULT_DIR="${RESULTS_DIR}/${TIMESTAMP}"
TEST_NAME="scale_${TARGET_SESSIONS}_${TIMESTAMP}"

cat << EOF
╔══════════════════════════════════════════════════════════════╗
║           YESRouter Scale Test - ${TARGET_SESSIONS} Sessions              ║
╠══════════════════════════════════════════════════════════════╣
║  Ramp Up:    ${RAMP_SEC}s                                              ║
║  Hold:       ${HOLD_SEC}s                                             ║
║  Ramp Down:  ${RAMPDOWN_SEC}s                                              ║
║  Repeats:    ${REPEAT_COUNT}                                               ║
╚══════════════════════════════════════════════════════════════╝
EOF

#=============================================================================
# Pre-flight checks
#=============================================================================
preflight_check() {
    log "Running pre-flight checks..."

    # Check VBNG is running
    if ! ssh ${VBNG_HOST} "pgrep -x yesrouter" > /dev/null; then
        log_err "yesrouter not running on VBNG"
        exit 1
    fi

    # Check blaster is available
    if ! ssh ${BLASTER_HOST} "which bngblaster" > /dev/null; then
        log_err "bngblaster not found on blaster host"
        exit 1
    fi

    # Check hugepages
    local hp=$(ssh ${VBNG_HOST} "cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages")
    if [ "$hp" -lt 1024 ]; then
        log_warn "Hugepages: ${hp} (recommend >= 1024)"
    fi

    log_ok "Pre-flight checks passed"
}

#=============================================================================
# Apply system tuning
#=============================================================================
apply_tuning() {
    log "Applying system tuning on VBNG..."

    ssh ${VBNG_HOST} << 'TUNE_EOF'
        # Network buffers
        sudo sysctl -w net.core.rmem_max=268435456 2>/dev/null || true
        sudo sysctl -w net.core.wmem_max=268435456 2>/dev/null || true
        sudo sysctl -w net.core.netdev_max_backlog=250000 2>/dev/null || true

        # Memory
        sudo sysctl -w vm.swappiness=10 2>/dev/null || true

        # Disable kernel features that interfere
        sudo sysctl -w net.ipv4.tcp_timestamps=0 2>/dev/null || true

        echo "Tuning applied"
TUNE_EOF

    log_ok "System tuning applied"
}

#=============================================================================
# Generate BNG Blaster config
#=============================================================================
generate_blaster_config() {
    local sessions=$1
    local rate=$((sessions / RAMP_SEC))
    [ $rate -lt 1 ] && rate=1

    log "Generating blaster config for ${sessions} sessions (rate: ${rate}/s)..."

    # BNG Blaster JSON config for scale testing
    # Using single VLAN with N:1 mode for multiple sessions
    local max_outstanding=$((sessions > 1000 ? 1000 : sessions))

    ssh ${BLASTER_HOST} "cat > /tmp/scale_test.json" << EOF
{
    "interfaces": {
        "access": [
            {
                "interface": "ens19",
                "type": "pppoe",
                "vlan-mode": "N:1",
                "outer-vlan": 100,
                "inner-vlan": 0
            }
        ]
    },
    "pppoe": {
        "reconnect": false,
        "discovery-timeout": 5,
        "discovery-retry": 3,
        "host-uniq": true,
        "service-name": "Internet"
    },
    "ppp": {
        "mru": 1492,
        "authentication": {
            "username": "user{session-global}@test",
            "password": "test",
            "timeout": 5,
            "retry": 3,
            "protocol": "PAP"
        },
        "lcp": {
            "conf-request-timeout": 1,
            "conf-request-retry": 10,
            "keepalive-interval": 30,
            "keepalive-retry": 3
        },
        "ipcp": {
            "enable": true,
            "request-ip": true,
            "request-dns1": false,
            "request-dns2": false,
            "conf-request-timeout": 1,
            "conf-request-retry": 10
        },
        "ip6cp": {
            "enable": false
        }
    },
    "sessions": {
        "count": ${sessions},
        "max-outstanding": ${max_outstanding},
        "start-rate": ${rate},
        "stop-rate": ${rate}
    }
}
EOF

    log_ok "Blaster config generated"
}

#=============================================================================
# Start metrics collection
#=============================================================================
start_metrics() {
    local run_id=$1
    log "Starting metrics collection (run ${run_id})..."

    # Start CPU/memory monitoring on VBNG
    ssh ${VBNG_HOST} "nohup bash -c '
        YESPID=\$(pgrep -x yesrouter)
        while true; do
            echo \"\$(date +%s),\$(ps -p \$YESPID -o %cpu,%mem,rss,vsz --no-headers 2>/dev/null || echo \"0,0,0,0\")\"
            sleep 1
        done
    ' > /tmp/metrics_${run_id}.csv 2>&1 &"

    # Start DPDK stats collection (if available)
    ssh ${VBNG_HOST} "nohup bash -c '
        while true; do
            echo \"show pppoe statistics\" | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null | grep -E \"^[A-Za-z]\" || true
            sleep 5
        done
    ' > /tmp/pppoe_stats_${run_id}.log 2>&1 &" || true

    log_ok "Metrics collection started"
}

#=============================================================================
# Stop metrics collection
#=============================================================================
stop_metrics() {
    local run_id=$1
    log "Stopping metrics collection..."

    ssh ${VBNG_HOST} "pkill -f 'metrics_${run_id}' 2>/dev/null || true"
    ssh ${VBNG_HOST} "pkill -f 'pppoe_stats_${run_id}' 2>/dev/null || true"

    # Copy results
    scp ${VBNG_HOST}:/tmp/metrics_${run_id}.csv "${RESULT_DIR}/" 2>/dev/null || true
    scp ${VBNG_HOST}:/tmp/pppoe_stats_${run_id}.log "${RESULT_DIR}/" 2>/dev/null || true

    log_ok "Metrics collected"
}

#=============================================================================
# Run single test
#=============================================================================
run_single_test() {
    local run_id=$1
    local sessions=$2

    log "=== Starting test run ${run_id} with ${sessions} sessions ==="

    # Start metrics
    start_metrics ${run_id}

    # Clear existing sessions
    ssh ${VBNG_HOST} "echo 'clear pppoe sessions' | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null" || true
    sleep 2

    # Run blaster
    log "Starting BNG Blaster..."
    local total_time=$((RAMP_SEC + HOLD_SEC + RAMPDOWN_SEC))

    ssh ${BLASTER_HOST} "sudo timeout ${total_time} bngblaster -C /tmp/scale_test.json \
        -r /tmp/report_${run_id}.json \
        -l /tmp/blaster_${run_id}.log \
        2>&1" || true

    # Wait for completion
    log "Test running for ${total_time}s..."
    sleep 5

    # Stop metrics
    stop_metrics ${run_id}

    # Copy blaster results
    scp ${BLASTER_HOST}:/tmp/report_${run_id}.json "${RESULT_DIR}/" 2>/dev/null || true
    scp ${BLASTER_HOST}:/tmp/blaster_${run_id}.log "${RESULT_DIR}/" 2>/dev/null || true

    # Get final session count from VBNG
    local vbng_sessions=$(ssh ${VBNG_HOST} "echo 'show pppoe sessions' | sudo socat - UNIX-CONNECT:/run/yesrouter/cli.sock 2>/dev/null | grep -c '^[0-9]'" || echo "0")

    log_ok "Run ${run_id} complete. VBNG sessions: ${vbng_sessions}"

    echo "${vbng_sessions}"
}

#=============================================================================
# Generate report
#=============================================================================
generate_report() {
    log "Generating test report..."

    # Parse metrics
    local avg_cpu=0
    local peak_cpu=0
    local avg_rss=0
    local peak_rss=0

    if [ -f "${RESULT_DIR}/metrics_1.csv" ]; then
        avg_cpu=$(awk -F',' '{sum+=$2; count++} END {printf "%.1f", sum/count}' "${RESULT_DIR}/metrics_1.csv" 2>/dev/null || echo "0")
        peak_cpu=$(awk -F',' 'BEGIN{max=0} {if($2>max)max=$2} END {printf "%.1f", max}' "${RESULT_DIR}/metrics_1.csv" 2>/dev/null || echo "0")
        avg_rss=$(awk -F',' '{sum+=$4; count++} END {printf "%.0f", sum/count/1024}' "${RESULT_DIR}/metrics_1.csv" 2>/dev/null || echo "0")
        peak_rss=$(awk -F',' 'BEGIN{max=0} {if($4>max)max=$4} END {printf "%.0f", max/1024}' "${RESULT_DIR}/metrics_1.csv" 2>/dev/null || echo "0")
    fi

    # Generate JSON report
    cat > "${RESULT_DIR}/report.json" << EOF
{
    "test_name": "${TEST_NAME}",
    "timestamp": "${TIMESTAMP}",
    "target_sessions": ${TARGET_SESSIONS},
    "ramp_seconds": ${RAMP_SEC},
    "hold_seconds": ${HOLD_SEC},
    "results": {
        "avg_cpu_percent": ${avg_cpu},
        "peak_cpu_percent": ${peak_cpu},
        "avg_rss_mb": ${avg_rss},
        "peak_rss_mb": ${peak_rss},
        "memory_per_session_kb": $(echo "scale=2; ${avg_rss} * 1024 / ${TARGET_SESSIONS}" | bc 2>/dev/null || echo "0")
    },
    "success_criteria": {
        "sessions_target_met": false,
        "cpu_within_budget": false,
        "ram_within_budget": false
    }
}
EOF

    log_ok "Report generated: ${RESULT_DIR}/report.json"

    # Print summary
    cat << EOF

╔══════════════════════════════════════════════════════════════╗
║                    TEST RESULTS SUMMARY                      ║
╠══════════════════════════════════════════════════════════════╣
║  Target Sessions:  ${TARGET_SESSIONS}
║  Average CPU:      ${avg_cpu}%
║  Peak CPU:         ${peak_cpu}%
║  Average RSS:      ${avg_rss} MB
║  Peak RSS:         ${peak_rss} MB
║  Memory/Session:   $(echo "scale=2; ${avg_rss} * 1024 / ${TARGET_SESSIONS}" | bc 2>/dev/null || echo "N/A") KB
╚══════════════════════════════════════════════════════════════╝

Results saved to: ${RESULT_DIR}/
EOF
}

#=============================================================================
# Main
#=============================================================================
main() {
    preflight_check
    apply_tuning
    generate_blaster_config ${TARGET_SESSIONS}

    # Run tests
    for i in $(seq 1 ${REPEAT_COUNT}); do
        run_single_test $i ${TARGET_SESSIONS}
        sleep 10  # Cool down between runs
    done

    generate_report

    log_ok "Scale test complete!"
}

main "$@"
