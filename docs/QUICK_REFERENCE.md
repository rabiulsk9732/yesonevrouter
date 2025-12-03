# YESRouter - Quick Reference Guide

## Project Summary

**YESRouter** is a high-performance, software-based Virtual Broadband Network Gateway (vBNG) designed for ISPs. It achieves 80 Gbps throughput on commodity x86 hardware using Intel DPDK, providing enterprise-grade routing, NAT, QoS, and firewall capabilities.

---

## Key Technologies Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Packet Processing** | Intel DPDK | Zero-copy, poll-mode driver packet processing |
| **Routing Lookup** | Radix Tree | Longest prefix matching (LPM) for IP routing |
| **Routing Protocol** | BGP (RFC 4271) | Dynamic routing, route distribution |
| **Session Protocol** | PPPoE, IPoE | Subscriber session termination |
| **NAT** | SNAT44, DNAT44 | Carrier-grade network address translation |
| **Filtering** | Stateful ACLs | Access control lists with connection tracking |
| **QoS** | Token Bucket + WFQ | Traffic classification and scheduling |
| **OS** | Linux Kernel 5.4+ | Foundation operating system |
| **Language** | C/C++11 | Implementation language |
| **Build** | CMake/Meson | Build system |

---

## High-Level Architecture

```
┌─────────────────────────────────────────────┐
│         Management Plane                     │
│  (CLI, Web UI, REST API, NETCONF/YANG)      │
└─────────────────────────────────────────────┘
                    ▲
                    │ Control Signals
                    │
┌──────────────────────────────────────────────┐
│      Control Plane                           │
│  ┌──────────┐  ┌─────────┐  ┌────────────┐ │
│  │Routing   │  │BGP      │  │ Session    │ │
│  │Table Mgr │  │Engine   │  │ Manager    │ │
│  └──────────┘  └─────────┘  └────────────┘ │
└──────────────────────────────────────────────┘
                    ▲
                    │ Forwarding Decisions
                    │
┌──────────────────────────────────────────────┐
│         Data Plane (DPDK)                    │
│  ┌─────────────────────────────────────────┐ │
│  │ RX → Classify → Filter → NAT → Lookup  │ │
│  │    → QoS → TX                           │ │
│  └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
         │         │         │
      [Subscribers] [Uplink] [Management]
```

---

## Core Modules Overview

### 1. vBNG (Virtual Broadband Network Gateway) Module
- **Function**: Subscriber session termination
- **Protocols**: PPPoE, IPoE (DHCP)
- **Capacity**: 128,000+ concurrent subscribers
- **Sub-modules**:
  - PPPoE Engine (PADI/PADO/PADR/PADS)
  - IPoE Engine (DHCP server)
  - Session Manager

### 2. Firewall Module
- **Function**: Packet filtering and access control
- **Features**: Stateful inspection, ACLs, IP sets
- **Performance**: <1μs per packet decision
- **Sub-modules**:
  - ACL Engine (rule matching)
  - Stateful Inspection (connection tracking)
  - IP Set Manager (millions of IPs)
  - Rate Limiter (token bucket)

### 3. CGNAT Module (Carrier-Grade NAT)
- **Function**: Network address translation at scale
- **Capacity**: 50,000+ subscribers per IP
- **Features**: SNAT44, DNAT44, session logging, IPv6 dual-stack
- **Sub-modules**:
  - NAT Translation Engine
  - Port Allocator
  - Session Logger (IPFIX/NetFlow)

### 4. QoS Module (Quality of Service)
- **Function**: Traffic classification and scheduling
- **Algorithms**: Token bucket, WFQ, Strict Priority
- **Features**: Per-subscriber queuing, hierarchical scheduling
- **Sub-modules**:
  - Traffic Classifier (DPI)
  - Scheduler
  - Policer Engine
  - Shaper Engine

### 5. Routing Module
- **Function**: IP packet forwarding and routing
- **Protocols**: BGP, Static routes, ECMP
- **Lookup**: Radix tree-based LPM <100ns
- **Sub-modules**:
  - Forwarding Engine (DPDK-based)
  - Routing Table Manager
  - BGP Engine
  - ARP/Neighbor Manager

### 6. Data Plane Module
- **Function**: High-performance packet processing
- **Technology**: Intel DPDK
- **Features**: Poll-mode drivers, huge pages, NUMA aware
- **Performance**: 80 Gbps throughput

### 7. Management Module
- **Function**: System configuration and monitoring
- **Interfaces**: CLI, Web UI, REST API, NETCONF/YANG
- **Features**: Real-time dashboards, logging, alerting

---

## Packet Processing Pipeline

```
INGRESS
   ↓
1. Packet arrives on interface
   ↓
2. Ethernet/VLAN processing
   ↓
3. IPsec processing (if configured)
   ↓
4. Classification (5-tuple, DPI, DSCP)
   ↓
5. Ingress ACL/Firewall check
   ↓
6. BNG Session lookup
   (If PPPoE/IPoE session)
   ↓
7. CGNAT Translation
   (If enabled for subscriber)
   ↓
8. Routing table lookup (LPM)
   ↓
9. Ingress QoS Policer
   (Rate limit check)
   ↓
10. Egress QoS Scheduler
    (Queue and prioritize)
    ↓
11. Egress ACL/Firewall check
    ↓
12. Encapsulation (if needed)
    ↓
13. ARP resolution (if needed)
    ↓
14. Egress QoS Shaper
    (Traffic shaping)
    ↓
EGRESS on appropriate interface
```

---

## Configuration Hierarchy

```yaml
system:
  hostname: yesrouter-1
  timezone: UTC
  syslog:
    server: 192.168.1.1
    port: 514

interfaces:
  physical:
    - name: ge-0/0/0
      ip: 10.0.0.1/24
      mtu: 1500
    - name: ge-0/0/1
      ip: 192.168.1.1/24

  virtual:
    - name: vlan100
      vlan-id: 100
      parent: ge-0/0/0

routing:
  static-routes:
    - destination: 0.0.0.0/0
      next-hop: 10.0.0.254

  bgp:
    local-asn: 65000
    peers:
      - ip: 10.0.0.254
        asn: 65001

bng:
  pppoe:
    enabled: true
    service-name: ISP

  ipoе:
    enabled: true
    dhcp-server: 192.168.1.5

cgnat:
  enabled: true
  pools:
    - name: pool1
      start-ip: 203.0.113.1
      end-ip: 203.0.113.254

firewall:
  acls:
    - name: ingress-acl
      rules:
        - action: accept
          protocol: tcp
          dport: 80
        - action: drop

qos:
  classes:
    - class-id: 1
      name: VoIP
      priority: 7
    - class-id: 2
      name: Video
      priority: 5
```

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **Throughput** | 80 Gbps | Per system |
| **Packet Rate** | 200+ Mpps | Million packets/sec |
| **Session Setup Rate** | 10,000+ sessions/sec | Combined PPPoE/IPoE |
| **Concurrent Sessions** | 100,000+ | Depends on profile complexity |
| **Routing Lookup** | <100 ns | Per packet |
| **Forwarding Decision** | <1 μs | Including QoS |
| **NAT Translation** | <500 ns | Per packet |
| **CPU Utilization** | 70-80% | For 80 Gbps throughput |
| **Latency** | <100 μs | Average packet latency |
| **Jitter** | <50 μs | Under normal load |

---

## Deployment Models

### 1. Single Router
```
Internet ←→ [YESRouter] ←→ Subscribers
```

### 2. Distributed Gateway (Multi-Site)
```
Internet
   ↓ (BGP)
├─ [YESRouter 1] ← VLAN → Subscribers Site 1
├─ [YESRouter 2] ← VLAN → Subscribers Site 2
└─ [YESRouter 3] ← VLAN → Subscribers Site 3
```

### 3. High Availability
```
Internet
   ↓ (BGP)
   |
┌──┴──┐
│ LB  │ (Load Balancer/VRRP)
└──┬──┘
   |
┌──┴───────────────────┐
│                      │
[Primary vBNG] ←sync→ [Standby vBNG]
   (Active)            (Hot-Standby)
   ↓                        ↓
Subscribers A          Subscribers B
```

---

## Common Configuration Tasks

### Enable PPPoE Subscriber Access
```yang
bng/pppoe {
  enabled: true
  service-name: "ISP"
  mtu: 1492
  ac-name: "Router1"
}
```

### Configure CGNAT
```yang
cgnat {
  enabled: true
  pools {
    pool1 {
      start-ip: 203.0.113.1
      end-ip: 203.0.113.254
      port-range: 1024-65535
    }
  }
  subscribers-per-ip: 100
}
```

### Setup BGP Peering
```yang
routing/bgp {
  local-asn: 65000
  peers {
    peer1 {
      neighbor-ip: 10.0.0.1
      remote-asn: 65001
      password: "secret"
    }
  }
}
```

### Configure QoS for Video Traffic
```yang
qos {
  classes {
    video {
      priority: 5
      rate-limit: 25000  # kbps
      burst-size: 1000   # KB
    }
  }
  policies {
    video-policy {
      match {
        protocol: tcp
        dport: 80,443
      }
      action: classfy
      class: video
    }
  }
}
```

---

## Monitoring & Troubleshooting Commands

```bash
# View active sessions
show bng sessions active
show bng sessions statistics

# View routing table
show routing table
show routing table summary

# View BGP status
show bgp summary
show bgp neighbors 10.0.0.1

# View interface statistics
show interfaces statistics
show interfaces ge-0/0/0 detail

# View NAT statistics
show cgnat statistics
show cgnat sessions active

# View firewall statistics
show firewall statistics
show firewall acl rules

# View QoS queues
show qos queues
show qos statistics

# Packet capture/trace
packet-capture interface ge-0/0/0 count 100
traffic-trace source 192.168.1.1 destination 10.0.0.1
```

---

## API Endpoints (REST)

### Sessions
- `GET /api/v1/sessions` - List all sessions
- `GET /api/v1/sessions/{id}` - Get session details
- `POST /api/v1/sessions/{id}/terminate` - Terminate session
- `GET /api/v1/sessions/statistics` - Session statistics

### Interfaces
- `GET /api/v1/interfaces` - List interfaces
- `GET /api/v1/interfaces/{name}/statistics` - Interface stats
- `PUT /api/v1/interfaces/{name}/config` - Update config
- `POST /api/v1/interfaces/{name}/up` - Bring up interface

### Routing
- `GET /api/v1/routes` - List routing table
- `POST /api/v1/routes` - Add route
- `DELETE /api/v1/routes/{id}` - Delete route
- `GET /api/v1/bgp/neighbors` - BGP peer status

### Firewall
- `GET /api/v1/firewall/acl` - List ACLs
- `PUT /api/v1/firewall/acl/{name}` - Update ACL
- `GET /api/v1/firewall/statistics` - Firewall stats

### QoS
- `GET /api/v1/qos/queues` - Queue status
- `GET /api/v1/qos/statistics` - QoS statistics
- `PUT /api/v1/qos/policy/{name}` - Update policy

### System
- `GET /api/v1/system/health` - System health
- `GET /api/v1/system/cpu-usage` - CPU utilization
- `GET /api/v1/system/memory-usage` - Memory utilization
- `GET /api/v1/system/uptime` - System uptime

---

## File Structure

```
yesrouter/
├── src/
│   ├── main.c                 # Entry point
│   ├── core/
│   │   ├── dpdk_init.c        # DPDK initialization
│   │   ├── cpu_scheduler.c    # CPU scheduling
│   │   ├── packet.h/c         # Packet structures
│   │   └── buffer_pool.h/c    # Memory management
│   ├── interfaces/
│   │   ├── interface.h/c      # Interface abstraction
│   │   ├── physical.c         # Physical interface driver
│   │   └── virtual.c          # Virtual interface (VLAN, LAG)
│   ├── routing/
│   │   ├── radix_tree.h/c     # LPM lookup
│   │   ├── route.h/c          # Routing table
│   │   └── bgp/
│   │       ├── bgp.h/c        # BGP protocol
│   │       ├── bgp_fsm.c      # BGP state machine
│   │       └── bgp_msg.c      # BGP messages
│   ├── forwarding/
│   │   ├── forward.h/c        # Packet forwarding
│   │   ├── arp.h/c            # ARP handling
│   │   └── checksum.c         # Checksum calculation
│   ├── access/
│   │   ├── pppoe.h/c          # PPPoE protocol
│   │   ├── dhcp.h/c           # DHCP server
│   │   └── auth.h/c           # Authentication (PAP/CHAP)
│   ├── session/
│   │   ├── session.h/c        # Session management
│   │   └── session_table.c    # Session storage
│   ├── firewall/
│   │   ├── acl.h/c            # ACL engine
│   │   ├── stateful.h/c       # Stateful inspection
│   │   ├── ipset.h/c          # IP set manager
│   │   └── rate_limiter.h/c   # Rate limiting
│   ├── nat/
│   │   ├── nat.h/c            # NAT translation
│   │   ├── port_alloc.h/c     # Port allocation
│   │   ├── nat_log.h/c        # NAT logging
│   │   └── ipv6.c             # IPv6 support
│   ├── qos/
│   │   ├── classifier.h/c     # Traffic classification
│   │   ├── scheduler.h/c      # Packet scheduling
│   │   ├── policer.h/c        # Rate policing
│   │   └── shaper.h/c         # Traffic shaping
│   ├── config/
│   │   ├── yang_model.yang    # YANG data model
│   │   └── config.h/c         # Configuration management
│   ├── logging/
│   │   ├── log.h/c            # Logging system
│   │   └── syslog.c           # Syslog integration
│   ├── monitoring/
│   │   ├── stats.h/c          # Statistics collection
│   │   ├── metrics.h/c        # Metrics export
│   │   └── health.h/c         # Health monitoring
│   ├── management/
│   │   ├── cli.h/c            # CLI interface
│   │   ├── rest_api.h/c       # REST API server
│   │   ├── netconf.h/c        # NETCONF interface
│   │   └── webui.c            # Web UI (optional)
│   └── utils/
│       ├── hash_table.h/c     # Hash table utility
│       ├── list.h/c           # List data structure
│       ├── memory.h/c         # Memory utilities
│       └── time.h/c           # Time utilities
├── tests/
│   ├── unit/
│   │   ├── test_routing.c
│   │   ├── test_nat.c
│   │   ├── test_qos.c
│   │   └── ...
│   ├── integration/
│   │   ├── test_pppoe_flow.c
│   │   ├── test_bgp_peering.c
│   │   └── ...
│   └── performance/
│       ├── benchmark_forwarding.c
│       ├── benchmark_nat.c
│       └── ...
├── docs/
│   ├── ARCHITECTURE.md        # Project architecture
│   ├── MODULES_BREAKDOWN.md   # Detailed module docs
│   ├── IMPLEMENTATION_TASKS.md# Project tasks
│   ├── API_REFERENCE.md       # REST API documentation
│   ├── CONFIG_GUIDE.md        # Configuration guide
│   ├── DEPLOYMENT_GUIDE.md    # Deployment guide
│   ├── TROUBLESHOOTING.md     # Troubleshooting guide
│   └── DEVELOPER_GUIDE.md     # Developer guide
├── config/
│   ├── yesrouter.conf         # Default configuration
│   └── yang/
│       └── yesrouter.yang     # YANG models
├── scripts/
│   ├── build.sh               # Build script
│   ├── test.sh                # Test script
│   ├── deploy.sh              # Deployment script
│   └── benchmark.sh           # Benchmark script
├── docker/
│   ├── Dockerfile             # Docker image
│   └── docker-compose.yml     # Docker compose
├── CMakeLists.txt             # Build configuration
├── README.md                  # Project README
├── LICENSE                    # License file
└── .gitignore                 # Git ignore rules
```

---

## Getting Started

### 1. Install Dependencies
```bash
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libdpdk-dev \
    libmicrohttpd-dev \
    libyang-dev \
    libjson-c-dev
```

### 2. Build Project
```bash
cd yesrouter
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### 3. Run with DPDK
```bash
sudo ./yesrouter \
    -l 0-3 \
    -n 4 \
    --proc-type=primary \
    -- \
    -c /etc/yesrouter/config.conf
```

### 4. Access Management Interface
```bash
# CLI
telnet localhost 23

# REST API
curl http://localhost:8080/api/v1/system/health

# Web UI
http://localhost:8000
```

---

## Support & Resources

- **Documentation**: `/root/vbng/docs/`
- **Configuration Examples**: Available in repo
- **API Reference**: REST API documentation
- **Troubleshooting**: Refer to TROUBLESHOOTING.md
- **Performance Tuning**: See performance guide

---

## License

YESRouter vBNG - High-Performance Virtual Broadband Network Gateway
[License Information]

---

**Document Version**: 1.0
**Last Updated**: December 2024
