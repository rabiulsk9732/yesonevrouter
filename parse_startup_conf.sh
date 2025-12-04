#!/bin/bash
#
# Parse VPP-style startup.conf
# Returns: EXEC_FILE and DPDK_DEVS
#

CONF_FILE="/root/vbng/config/startup.conf"

if [ ! -f "$CONF_FILE" ]; then
    return 1
fi

# Extract DPDK devices
DPDK_DEVS=$(awk '/^dpdk \{/,/^\}/' "$CONF_FILE" | grep '^\s*dev ' | awk '{print $2}' | tr '\n' ' ')

# Extract exec file path from unix section
EXEC_FILE=$(awk '/^unix \{/,/^\}/' "$CONF_FILE" | grep -E '^\s*(exec|startup-config) ' | awk '{print $2}')

# Export for caller
export DPDK_DEVS
export EXEC_FILE
