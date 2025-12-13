# YESRouter - Project Architecture & Documentation

## 1. Project Overview

### Project Name
**YESRouter vBNG - High-Performance Virtual Broadband Network Gateway**

### Description
YESRouter is a cost-efficient, software-based, high-performance virtual router designed for Broadband Internet Service Providers (ISPs). It achieves enterprise-grade capability running on commodity x86 servers, delivering up to 80 Gbps throughput while serving hundreds of thousands of clients.

### Key Technologies
- **Intel Data Plane Development Kit (DPDK)** - High-performance packet processing
- **x86-based Architecture** - Commodity hardware compatibility
- **Modern Network Protocols** - PPPoE, IPoE, BGP, L2TP
- **Linux Kernel** - Foundation OS
- **C/C++** - Core implementation language

### Target Users
- Broadband Service Providers (ISPs)
- Regional/Local Carriers
- Wireless Service Providers
- Network Infrastructure Operators

### Performance Metrics
- **Throughput**: Up to 80 Gbps
- **Subscriber Capacity**: Hundreds of thousands of clients
- **Hardware**: Standard x86 commodity servers
- **Cost Reduction**: Significant TCO reduction vs. proprietary solutions

---

## 2. Core Modules & Components

### 2.1 Virtual Broadband Network Gateway (vBNG) Module

#### Purpose
vBNG is the primary capability of YESRouter, handling subscriber session termination and management.

#### Responsibilities
- Subscriber session lifecycle management
- Protocol termination (PPPoE, IPoE)
- Subscriber authentication and authorization
- IP address assignment and management
- Session-based traffic steering
- Subscriber rate limiting and policing

#### Key Features
- **PPPoE Support** - Point-to-Point Protocol over Ethernet termination
- **IPoE Support** - IP over Ethernet session handling
- **BGP Integration** - Border Gateway Protocol routing
- **Multi-access technology support** - DSL, Fiber, Wireless
- **Zero-touch Subscriber Management** - Automation across OLT and Wireless devices
- **Subscriber Scaling** - Capable of handling 2,000 to 128,000+ subscribers

#### Sub-Components
1. **PPPoE Engine**
   - PPPoE session discovery and establishment
   - PPP protocol negotiation
   - Authentication (PAP/CHAP)
   - Subscriber binding and state management

2. **IPoE Engine**
   - DHCP/DHCPv6 handling
   - IPv4/IPv6 address assignment
   - Session identification (MAC-based, Interface-based)
   - VLAN-based subscriber separation

3. **Session Manager**
   - Session state tracking
   - Timeout management
   - Session modification and termination
   - Statistics collection per session

4. **Routing Integration**
   - BGP peer management
   - Route announcement
   - Traffic steering based on routing policies

---

### 2.2 Firewall Module

#### Purpose
Provides comprehensive packet filtering and security capabilities to protect the network and manage traffic policies.

#### Responsibilities
- Stateful packet inspection and filtering
- Access Control List (ACL) enforcement
- IP set management for large-scale filtering
- Traffic policy enforcement
- Protocol inspection
- DoS/DDoS mitigation

#### Key Features
- **Stateful Filtering** - Complete connection state tracking
- **ACL Support** - Fine-grained access control policies
  - Source/destination IP filtering
  - Protocol-based rules
  - Port-based filtering
  - VLAN-based policies
- **Large IP Sets** - Efficient storage and lookup for millions of IP addresses
- **Rate Limiting** - Per-flow and per-session rate limiting
- **Anti-DDoS** - Connection rate limiting, SYN flood protection
- **Protocol-specific Rules** - DNS, HTTP, HTTPS handling

#### Sub-Components
1. **ACL Engine**
   - Rule compilation and optimization
   - Rule matching engine (O(1) lookup)
   - Action execution (accept, drop, mark, redirect)

2. **Stateful Inspection Engine**
   - Connection state tracking
   - TCP sequence number validation
   - State timeout management
   - Connection table management

3. **IP Set Manager**
   - Hash-based IP lookup
   - IPv4 and IPv6 support
   - Dynamic updates
   - Memory-efficient storage

4. **Rate Limiter**
   - Token bucket algorithm
   - Per-flow tracking
   - Burst handling
   - Congestion detection

---

### 2.3 Carrier-Grade NAT (CG-NAT) Module

#### Purpose
Provides highly scalable Network Address Translation (NAT) to enable IPv4 address sharing and facilitate IPv6 migration.

#### Responsibilities
- IPv4 address translation and reuse
- Subscriber-to-address mapping
- Port allocation and management
- Session logging for regulatory compliance
- IPv6 co-existence support
- Stateful NAT operations

#### Key Features
- **SNAT44** - Source NAT for IPv4 to IPv4 translation
- **DNAT44** - Destination NAT for port forwarding
- **Various Translation Algorithms** - 1-to-1, many-to-one, endpoint-independent mapping
- **High Subscriber Support** - 50,000+ subscribers per instance
- **Dynamic Port Allocation** - Efficient port management
- **Session Logging** - Detailed logging for compliance (IPFIX, NetFlow)
- **IPv6 Integration** - Dual-stack support for IPv6 transition

#### Sub-Components
1. **NAT Translation Engine**
   - Address mapping table management
   - Port allocation logic
   - Translation table lookup and update
   - Flow state management

2. **Port Allocator**
   - Port range management
   - Dynamic allocation/deallocation
   - Port recycling
   - Allocation algorithm (sequential, random, etc.)

3. **Session Logger**
   - IPFIX/NetFlow export
   - Detailed session logging
   - Regulatory compliance tracking
   - Telemetry collection

4. **IPv6 Coexistence Layer**
   - Dual-stack routing
   - IPv4/IPv6 address mapping
   - NAT64 support (if needed)
   - Transition mechanism support

---

### 2.4 Quality of Service (QoS) Module

#### Purpose
Manages traffic classification, prioritization, and shaping to ensure optimal network performance and SLA compliance.

#### Responsibilities
- Traffic classification and marking
- Priority-based packet scheduling
- Traffic shaping and policing
- Bandwidth management
- Queue management
- SLA enforcement

#### Key Features
- **Traffic Classification**
  - Deep Packet Inspection (DPI) for application identification
  - 5-tuple flow identification
  - DSCP/CoS marking
  - VPN traffic detection

- **Traffic Policing**
  - Token bucket-based rate limiting
  - Subscriber-level policing
  - Uplink/downlink asymmetric policing
  - Burst handling

- **Traffic Shaping**
  - Hierarchical queuing (H-QoS)
  - Per-subscriber bandwidth allocation
  - Class-based queuing
  - FIFO, Priority Queue, WFQ scheduling

- **Accurate Traffic Recognition**
  - Layer 4-7 protocol identification
  - Application detection
  - Video/streaming detection
  - VoIP detection

#### Sub-Components
1. **Traffic Classifier**
   - Flow identification (5-tuple, more)
   - Protocol detection
   - DPI engine
   - Marking and tagging

2. **Scheduler**
   - Priority queue management
   - Weighted Fair Queuing (WFQ)
   - Strict priority scheduling
   - Queue state tracking

3. **Policer Engine**
   - Token bucket management
   - Rate enforcement
   - Congestion detection
   - Action selection (pass, mark, drop)

4. **Shaper Engine**
   - Hierarchical queue management
   - Bandwidth allocation
   - Queue depth management
   - Delay tracking

---

### 2.5 Core Routing Module

#### Purpose
Handles fundamental packet routing, IP forwarding, and routing protocol management.

#### Responsibilities
- IP packet forwarding
- Routing table management
- ECMP (Equal-Cost Multi-Path) support
- Routing protocol implementation
- Next-hop resolution
- MTU management

#### Key Features
- **High-Speed Forwarding** - DPDK-based forwarding plane
- **BGP Support** - Dynamic routing protocol
- **Static Routing** - Manual route configuration
- **ECMP** - Load balancing across multiple paths
- **VRF** - Virtual Routing and Forwarding for multi-tenant support
- **Fast Reroute** - Rapid failover on link failure

#### Sub-Components
1. **Forwarding Engine**
   - Packet lookup and forwarding
   - DPDK integration
   - Fast path processing
   - Exception handling

2. **Routing Table Manager**
   - Route storage and lookup
   - Trie-based prefix matching
   - Route updates and synchronization
   - RIB/FIB management

3. **BGP Engine**
   - BGP session management
   - Route advertisement/withdrawal
   - Route filtering
   - BGP state machine

4. **Neighbor/ARP Management**
   - ARP resolution
   - Neighbor table management
   - MAC address learning
   - L2/L3 binding

---

### 2.6 Management & Monitoring Module

#### Purpose
Provides system management, configuration, monitoring, and diagnostics capabilities.

#### Responsibilities
- System configuration management
- Real-time statistics collection
- Performance monitoring
- Logging and auditing
- Fault detection and alerting
- CLI/API access

#### Key Features
- **Web-Based Manager** - Single pane of glass view
- **CLI Interface** - Command-line configuration
- **NETCONF/YANG** - Standards-based management
- **Real-time Dashboards** - Performance visualization
- **Alerts & Notifications** - System event alerting
- **Troubleshooting Tools** - Packet capture, trace, diagnostics

#### Sub-Components
1. **Configuration Manager**
   - Configuration file parsing and validation
   - Runtime configuration updates
   - Configuration persistence
   - Rollback capabilities

2. **Monitoring Engine**
   - Real-time statistics collection
   - Performance metrics tracking
   - Alert threshold monitoring
   - Anomaly detection

3. **Logging System**
   - System logging (syslog)
   - Debug logging with levels
   - Session logging
   - Audit trail

4. **API Layer**
   - REST API for external integration
   - WebSocket for real-time updates
   - gRPC for high-performance management
   - Authentication and authorization

---

### 2.7 Data Plane Processing Module

#### Purpose
Core packet processing engine utilizing DPDK for high-performance operations.

#### Responsibilities
- Zero-copy packet processing
- Memory management
- CPU core utilization
- Interrupt handling
- Performance optimization
- NUMA awareness

#### Key Features
- **DPDK Integration** - Intel Data Plane Development Kit
- **Poll Mode Drivers** - Zero-interrupt packet processing
- **Memory Pools** - Pre-allocated, lock-free packet buffers
- **CPU Affinity** - Thread-to-core pinning
- **NUMA Support** - Non-Uniform Memory Architecture optimization
- **Hugepages** - Large page support for TLB efficiency

#### Sub-Components
1. **Packet Buffer Manager**
   - Memory pool management
   - Buffer allocation/deallocation
   - Ring buffers for lock-free operations
   - Memory accounting

2. **CPU Scheduler**
   - CPU core allocation
   - Thread scheduling
   - Load balancing across cores
   - Priority management

3. **Performance Tuning**
   - NUMA optimization
   - Cache optimization
   - Instruction pipeline optimization
   - SIMD utilization

---

## 3. System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Management & Monitoring                       │
│              (CLI, Web Manager, NETCONF, REST API)              │
└─────────────────────────────────────────────────────────────────┘
                               ▲
                               │
┌──────────────────────────────────────────────────────────────────┐
│                        Control Plane                             │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐    │
│  │ Routing     │  │ BGP Engine   │  │ Configuration Mgr   │    │
│  │ Table Mgr   │  │              │  │                     │    │
│  └─────────────┘  └──────────────┘  └─────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                               ▲
                               │
┌──────────────────────────────────────────────────────────────────┐
│                        Data Plane (DPDK)                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Core Packet Processing Pipeline            │  │
│  │                                                          │  │
│  │  ┌────────────┬────────────┬────────────┬────────────┐  │  │
│  │  │  Ingress   │ Classifier │  Policer   │ Firewall   │  │  │
│  │  │ Interface  │   (QoS)    │   (QoS)    │   Engine   │  │  │
│  │  └────────────┴────────────┴────────────┴────────────┘  │  │
│  │                        ▼                                 │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  Session Manager (BNG) & NAT Translation (CGNAT)   │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  │                        ▼                                 │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  IP Forwarding & Routing Lookup                    │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  │                        ▼                                 │  │
│  │  ┌────────────┬────────────┬────────────┬────────────┐  │  │
│  │  │  Shaper    │  Scheduler │ Egress     │ Encap      │  │  │
│  │  │  (QoS)     │   (QoS)    │ Processing │ Engine     │  │  │
│  │  └────────────┴────────────┴────────────┴────────────┘  │  │
│  │                        ▼                                 │  │
│  │  ┌─────────────────────────────────────────────────────┐ │  │
│  │  │         Egress Interface & TX                       │ │  │
│  │  └─────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Packet Buffer Manager | CPU Scheduler | NUMA Manager   │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘

                              ▲
                              │
              ┌───────────────┼───────────────┐
              │               │               │
        ┌─────────────┐ ┌──────────────┐ ┌─────────────┐
        │ Subscriber  │ │ Uplink       │ │ Management  │
        │ Interfaces  │ │ Interfaces   │ │ Interface   │
        │ (Multiple)  │ │ (BGP/BGP)    │ │             │
        └─────────────┘ └──────────────┘ └─────────────┘
```

---

## 4. Data Flow

### 4.1 Subscriber Ingress Traffic Flow

1. **Packet Arrival** → Ingress interface receives packet
2. **Classification** → QoS classifier identifies flow (5-tuple, L7 detection)
3. **Policing** → Subscriber-level rate limit check
4. **Firewall** → ACL/stateful inspection check
5. **BNG Session Lookup** → Identify subscriber session
6. **NAT Translation** → Apply CGNAT translation (if configured)
7. **Routing Lookup** → Determine outgoing interface
8. **Shaping/Scheduling** → Apply QoS queuing (priority, rate limit)
9. **Egress** → Send packet out on determined interface

### 4.2 Subscriber Egress Traffic Flow

1. **Packet from Uplink** → Reverse NAT translation
2. **Session Lookup** → Map to correct subscriber
3. **Classification** → Identify traffic type
4. **Policing** → Rate limit check
5. **Firewall** → Egress ACL check
6. **Routing** → Determine subscriber interface
7. **Scheduling** → Apply per-subscriber QoS
8. **Encapsulation** → PPP/VLAN encapsulation if needed
9. **Subscriber Interface TX** → Transmit to subscriber

---

## 5. Configuration Model

### 5.1 Major Configuration Sections

```
YESROUTER_CONFIG
├── System
│   ├── Hostname
│   ├── Syslog
│   ├── NTP
│   └── SNMP
├── Interfaces
│   ├── Physical Interfaces
│   │   ├── Speed/Duplex
│   │   └── MTU
│   ├── Logical Interfaces
│   │   ├── VLAN
│   │   ├── LAG (Link Aggregation)
│   │   └── Tunnel
│   └── Subscriber Interfaces
│       ├── PPPoE Pools
│       └── IPoE Pools
├── Routing
│   ├── Static Routes
│   ├── BGP Configuration
│   │   ├── BGP Peers
│   │   ├── Route Policies
│   │   └── Community Handling
│   └── ECMP
├── BNG Configuration
│   ├── PPPoE Settings
│   │   ├── Access Concentrator Name
│   │   ├── MTU
│   │   └── Idle Timeout
│   ├── IPoE Settings
│   │   ├── DHCP Server IP
│   │   └── VLAN Handling
│   └── Subscriber Policies
│       ├── Default Policies
│       └── Per-User Policies
├── CGNAT Configuration
│   ├── Address Pools
│   ├── Port Allocation
│   ├── Logging Rules
│   └── Subscriber Limits
├── Firewall Rules
│   ├── ACL Lists
│   ├── IP Sets
│   └── Connection Limits
├── QoS Configuration
│   ├── Traffic Classes
│   ├── Priority Queues
│   ├── Shaper Profiles
│   └── Policer Rules
└── Management
    ├── Users & RBAC
    ├── Authentication
    └── API Settings
```

---

## 6. Deployment Topology

### 6.1 Typical ISP Deployment

```
                    Internet / Upstream
                            │
                    ┌───────────────────┐
                    │  BGP Peers / Core │
                    │     Routers       │
                    └───────────────────┘
                            │
                 (BGP Uplink - 100GbE)
                            │
    ┌───────────────────────────────────────────┐
        │    YESRouter Cluster (HA)         │
        │  ┌─────────────┐  ┌─────────────┐ │
        │  │Primary vBNG │  │Standby vBNG │ │
        │  │(Active)     │  │(Standby)    │ │
        │  └─────────────┘  └─────────────┘ │
        │         │              │          │
        │    Shared State / Sync │          │
        └───────────────────────────────────┘
                │          │          │
        (VLAN Interfaces - 10GbE each)
                │          │          │
        ┌───────┼──────────┼────────┐
        │       │          │        │
    ┌─────┐ ┌────────┐ ┌─────────┐ │
    │DSLAM│ │  OLT   │ │  WISP   │ │
    │     │ │ (Fiber)│ │ (Radio) │ │
    └─────┘ └────────┘ └─────────┘ │
        │       │          │       │
    [Subscribers]      [Subscribers]
```

---

## 7. Performance Characteristics

### 7.1 Expected Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Throughput | 80 Gbps | Per system, on single CPU socket |
| Subscribers per System | 100,000+ | Depends on profile complexity |
| Session Setup Rate | 10,000+ sessions/sec | PPPoE/IPoE combined |
| Packet Rate | 200+ Mpps | Million packets per second |
| Latency | < 100 μs | Average packet latency |
| Jitter | < 50 μs | Under normal load |
| CPU Utilization | 70-80% | For 80 Gbps throughput |
| Memory | 8-32 GB | Depending on configuration |

---

## 8. High Availability & Failover

### 8.1 HA Architecture

- **Active-Standby Mode** - Primary handles all traffic, standby ready
- **Session Synchronization** - Real-time replication to standby
- **Sub-second Failover** - Rapid recovery on primary failure
- **Shared State** - Database/cache synchronization
- **Health Monitoring** - Continuous primary health checks

### 8.2 Redundancy Options

1. **Subscriber Interface Redundancy** - Multi-homed subscriber connectivity
2. **Uplink Redundancy** - Multiple BGP connections
3. **Data Center Redundancy** - Geographic distribution
4. **Configuration Backup** - Regular config snapshots

---

## 9. Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| OS | Linux | Kernel 5.4+ |
| Packet Processing | DPDK | 21.11+ |
| Routing Protocol | BGP | RFC 4271 |
| Management | YANG/NETCONF | RFC 6241+ |
| Language | C/C++ | C11/C++14 |
| Compiler | GCC/LLVM | GCC 9.0+, LLVM 10+ |
| Network Libraries | libc, libmnl | Standard |
| Hardware | Intel x86 | Xeon, i7 series |

---

## 10. Security Considerations

1. **Firewall Protection** - Stateful inspection of all traffic
2. **ACL Enforcement** - Fine-grained access control
3. **DDoS Mitigation** - Connection rate limiting
4. **Encrypted Management** - SSL/TLS for APIs
5. **RBAC** - Role-based access control
6. **Audit Logging** - Comprehensive activity logging
7. **Regular Updates** - Security patch deployment
8. **Isolated Control Plane** - Separate management network

---

## 11. Scalability Considerations

1. **Horizontal Scaling** - Add more systems in cluster
2. **Software Upgrades** - Easy feature addition without hardware replacement
3. **Capacity Planning** - Linear scaling with added systems
4. **Multi-threaded Design** - Full CPU core utilization
5. **Load Balancing** - Distribute subscriber load across systems
6. **Geographic Distribution** - Multi-site deployment

---

## 12. Summary

YESRouter provides a comprehensive, high-performance software-based Virtual Broadband Network Gateway (vBNG) solution. Its modular architecture enables flexible deployment for various ISP scenarios, from small regional carriers to large-scale operations. The use of DPDK and commodity x86 hardware provides exceptional performance at lower total cost of ownership compared to proprietary hardware-based solutions.
