# Source directory CMakeLists.txt

# DPDK module (must be before core)
add_subdirectory(dpdk)

# Configuration module
add_subdirectory(config)

# Logging module
add_subdirectory(logging)

# Monitoring module
add_subdirectory(monitoring)

# Core module
add_subdirectory(core)

# Interfaces module
add_subdirectory(interfaces)

# Routing module
add_subdirectory(routing)

# BGP module
# add_subdirectory(bgp)

# Network module (ARP/Neighbor)
add_subdirectory(network)

# Authentication module
add_subdirectory(auth)

# CLI module
add_subdirectory(cli)

# Forwarding module
add_subdirectory(forwarding)

# Access module (PPPoE, IPoE)
# add_subdirectory(access)

# Session module
# add_subdirectory(session)

# Firewall module
# add_subdirectory(firewall)

# CGNAT module
# add_subdirectory(cgnat)

# QoS module
# add_subdirectory(qos)

# Management module
# add_subdirectory(management)

# Note: Subdirectories will be uncommented as modules are implemented
