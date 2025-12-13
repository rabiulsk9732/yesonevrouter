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

# Network module (ARP/Neighbor)
add_subdirectory(network)

# Export module (IPFIX/NetFlow)
add_subdirectory(export)

# Routing module
add_subdirectory(routing)

# Management modules
add_subdirectory(ippool)
add_subdirectory(qos)
add_subdirectory(radius)
add_subdirectory(pppoe)
add_subdirectory(auth)
add_subdirectory(management)

# CLI module
add_subdirectory(cli)

# Forwarding module
add_subdirectory(forwarding)

# CGNAT/NAT module
add_subdirectory(nat)

# IPv6 module
add_subdirectory(ipv6)

# High Availability
add_subdirectory(ha)

# Main executable
# (Handled by parent CMakeLists usually, or strict lib definition here)
