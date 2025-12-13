# YESRouter - Detailed Modules Breakdown

## Module Hierarchy

```
YESROUTER
├── 1. vBNG Module (Virtual Broadband Network Gateway)
│   ├── 1.1 PPPoE Engine
│   ├── 1.2 IPoE Engine
│   ├── 1.3 Session Manager
│   └── 1.4 Routing Integration
├── 2. Firewall Module
│   ├── 2.1 ACL Engine
│   ├── 2.2 Stateful Inspection Engine
│   ├── 2.3 IP Set Manager
│   └── 2.4 Rate Limiter
├── 3. CGNAT Module (Carrier-Grade NAT)
│   ├── 3.1 NAT Translation Engine
│   ├── 3.2 Port Allocator
│   ├── 3.3 Session Logger
│   └── 3.4 IPv6 Coexistence Layer
├── 4. QoS Module (Quality of Service)
│   ├── 4.1 Traffic Classifier
│   ├── 4.2 Scheduler
│   ├── 4.3 Policer Engine
│   └── 4.4 Shaper Engine
├── 5. Routing Module
│   ├── 5.1 Forwarding Engine
│   ├── 5.2 Routing Table Manager
│   ├── 5.3 BGP Engine
│   └── 5.4 Neighbor/ARP Manager
├── 6. Data Plane Module
│   ├── 6.1 Packet Buffer Manager
│   ├── 6.2 CPU Scheduler
│   └── 6.3 Performance Tuning
└── 7. Management Module
    ├── 7.1 Configuration Manager
    ├── 7.2 Monitoring Engine
    ├── 7.3 Logging System
    └── 7.4 API Layer
```

---

## 1. vBNG Module (Virtual Broadband Network Gateway)

### Purpose & Role
The vBNG module is the core subscriber access handling component. It manages subscriber session lifecycle, including authentication, authorization, and session termination across multiple access technologies (PPPoE, IPoE).

### Key Interfaces
- **Input**: Raw subscriber frames from access network (DSL, Fiber, Wireless)
- **Output**: IP packets routed to upstream network
- **Control**: Session management commands from management plane
- **Monitoring**: Session statistics and events

### Data Structures
```c
// Session Entry
struct bng_session {
    uint32_t session_id;           // Unique session identifier
    uint32_t subscriber_id;        // Subscriber/account ID
    char username[256];             // PPP username
    char password[256];             // PPP password (encrypted)

    // Session State
    enum { PPP_IDLE, PPP_ACTIVE, PPP_TERMINATING } ppp_state;
    time_t session_start_time;
    time_t last_activity_time;

    // IP Configuration
    struct in_addr ipv4_addr;       // Assigned IPv4 address
    struct in_addr ipv4_gw;         // IPv4 gateway
    struct in6_addr ipv6_addr;      // Assigned IPv6 address

    // Access Info
    uint32_t vlan_id;               // VLAN for session
    uint8_t mac_address[6];         // Subscriber MAC
    uint32_t interface_index;       // Physical interface

    // Accounting
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t packets_sent;
    uint32_t packets_received;
};

// PPP Control Protocol (LCP/IPCP/IP6CP state)
struct ppp_state {
    uint32_t magic_number;
    uint8_t identifier;
    enum { INITIAL, STARTING, CLOSED, STOPPED, CLOSING, STOPPING, REQSENT, ACKRCVD, ACKSENT, OPENED } state;
    uint16_t mru;                   // Maximum Receive Unit
    uint16_t mtu;                   // Maximum Transmission Unit
};
```

### 1.1 PPPoE Engine Sub-Module

#### Responsibilities
- PPPoE frame parsing and generation
- PADI/PADO/PADR/PADS flow handling
- Session Discovery and establishment
- PPP session multiplexing

#### Data Processing
```
Incoming PPPoE Frame:
1. Receive PPPoE frame from DSL/Fiber
2. Parse PPPoE header (version, type, code)
3. Extract session ID or handle discovery
4. Demultiplex to appropriate session handler
5. Pass PPP frame to PPP handler

Outgoing PPPoE Response:
1. Receive response from PPP handler
2. Add PPPoE header with session ID
3. Add Ethernet frame
4. Transmit on physical interface
```

#### Key Algorithms
- PPP PAP/CHAP Authentication
- Magic Number negotiation
- LCP (Link Control Protocol) state machine
- IPCP (IP Control Protocol) negotiation

### 1.2 IPoE Engine Sub-Module

#### Responsibilities
- DHCP server handling
- DHCPv6 server handling
- Session identification (MAC, Interface, VLAN-based)
- IPv4/IPv6 address pool management

#### DHCP Request Processing
```
DHCP Request:
1. Receive DHCP DISCOVER
2. Identify subscriber (MAC address lookup)
3. Select IP address from pool
4. Create/update session entry
5. Send DHCP OFFER
6. On DHCP REQUEST: Send DHCP ACK with binding
7. Session active until lease expires or DHCP RELEASE
```

#### DHCPv6 Support
- Prefix Delegation (PD)
- DNS server announcement
- Stateful address allocation
- IA_NA (Identity Association for Non-temporary Addresses)

### 1.3 Session Manager Sub-Module

#### Responsibilities
- Session storage and lookup (hash table, tree)
- Session state transitions
- Timeout management
- Session statistics
- Session modification (IP change, QoS update, etc.)
- Session termination cleanup

#### Session Lifecycle
```
PPPoE Session:
IDLE → DISCOVERY → AUTHENTICATION → ACTIVE → (ACTIVE) → TERMINATION → CLOSED

IPoE Session:
IDLE → DHCP_DISCOVER → DHCP_OFFER → DHCP_REQUEST → ACTIVE → LEASE_TIMEOUT/RELEASE → CLOSED
```

#### Storage Optimization
- Primary: Hash table (O(1) lookup) by session ID
- Secondary: B-tree by username (for authentication lookup)
- Tertiary: Radix tree by IP address (for reverse lookup)
- Cache: Recently used sessions in L1 cache

### 1.4 Routing Integration Sub-Module

#### Responsibilities
- BGP route management on behalf of subscribers
- Route announcement/withdrawal
- Per-session routing policies
- Traffic steering based on subscriber routes

---

## 2. Firewall Module

### Purpose & Role
Provides comprehensive packet filtering, access control, and security enforcement for all traffic passing through the router.

### Key Interfaces
- **Input**: All packets from ingress interfaces
- **Output**: Accept/Drop/Mark decisions
- **Control**: ACL configuration, IP set updates
- **Monitoring**: Packet counters, blocked traffic stats

### 2.1 ACL Engine Sub-Module

#### Data Structures
```c
struct acl_rule {
    uint32_t rule_id;
    uint32_t priority;              // Lower = higher priority
    enum { INGRESS, EGRESS } direction;
    enum { ACCEPT, DROP, MARK, REDIRECT } action;

    // Match Conditions
    struct {
        uint32_t src_ip;
        uint32_t src_mask;
        uint32_t dst_ip;
        uint32_t dst_mask;
        uint16_t src_port_start;
        uint16_t src_port_end;
        uint16_t dst_port_start;
        uint16_t dst_port_end;
        uint8_t protocol;            // TCP, UDP, ICMP, etc.
        uint32_t vlan_id;
        uint8_t dscp;
    } match;

    // Action Parameters
    struct {
        uint8_t mark_value;         // For MARK action
        uint32_t redirect_interface; // For REDIRECT action
    } params;

    // Statistics
    uint64_t packet_count;
    uint64_t byte_count;
};

struct acl_list {
    uint32_t list_id;
    char name[64];
    struct acl_rule *rules;         // Array of rules
    uint32_t rule_count;
    uint32_t applied_count;         // How many interfaces use this list
};
```

#### Rule Matching Algorithm
```
For each packet:
1. Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
2. Extract additional fields (VLAN, DSCP)
3. For each rule in priority order:
   a. Check if packet matches all conditions
   b. If match found:
      - Increment counters
      - Perform action
      - Return result
4. If no rule matches: Default action (allow or deny)
```

#### Optimization Techniques
- **Rule Compilation**: Convert rules to efficient ternary match (TCAMs)
- **Caching**: Cache recently matched rules
- **Parallel Processing**: SIMD for rule matching on modern CPUs
- **Bloom Filters**: Quick rejection of non-matching rules

### 2.2 Stateful Inspection Engine Sub-Module

#### Connection Tracking
```c
struct connection_state {
    // 5-tuple identifying the flow
    struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
    } flow;

    // TCP Sequence Tracking (TCP only)
    struct {
        uint32_t client_seq;
        uint32_t server_seq;
        uint32_t client_ack;
        uint32_t server_ack;
    } tcp_state;

    // State Information
    enum { NEW, ESTABLISHED, RELATED, INVALID } state;
    time_t creation_time;
    time_t last_seen;
    uint64_t bytes_sent;
    uint64_t bytes_received;
};
```

#### TCP State Machine
```
NEW → ESTABLISHED → CLOSED (normal termination)
   → INVALID (malformed packets)
   → TIMEOUT (connection idle)
```

#### Stateful Filtering Rules
- Allow only ESTABLISHED connections in reverse direction
- Detect and block TCP sequence number attacks
- Timeout inactive connections
- Track ICMP error messages as RELATED

### 2.3 IP Set Manager Sub-Module

#### Purpose
Efficiently store and lookup millions of IP addresses for complex filtering rules.

#### Data Structure Options
```c
// Option 1: Hash Table (for random IPs)
struct ip_set_hashtable {
    struct hash_table *table;       // hash_table[hash(ip)] → list of IPs
    uint32_t ip_count;
    char name[64];
};

// Option 2: Radix Tree (for CIDR ranges)
struct ip_set_radix {
    struct radix_tree *tree;        // Efficient prefix matching
    uint32_t ip_count;
    char name[64];
};

// Option 3: Bitmap (for sequential IPs)
struct ip_set_bitmap {
    uint8_t *bitmap;                // Bit per IP (memory intensive)
    uint32_t base_ip;
    uint32_t ip_range;
};
```

#### Lookup Operation
```
ip_set_lookup(set, ip_address):
1. Hash the IP address
2. Lookup in appropriate structure
3. Return TRUE if IP in set, FALSE otherwise
Time Complexity: O(1) average, O(log n) worst case
```

### 2.4 Rate Limiter Sub-Module

#### Token Bucket Algorithm
```c
struct token_bucket {
    uint32_t rate;                  // Tokens per second
    uint32_t burst_size;            // Maximum tokens
    uint32_t current_tokens;
    time_t last_refill_time;
};

bool can_pass_packet(struct token_bucket *bucket, uint32_t packet_size) {
    time_t now = current_time();

    // Refill tokens based on elapsed time
    time_t elapsed = now - bucket->last_refill_time;
    uint32_t new_tokens = elapsed * bucket->rate;
    bucket->current_tokens = MIN(bucket->burst_size,
                                  bucket->current_tokens + new_tokens);
    bucket->last_refill_time = now;

    // Check if packet can pass
    if (bucket->current_tokens >= packet_size) {
        bucket->current_tokens -= packet_size;
        return true;
    }
    return false;
}
```

---

## 3. CGNAT Module (Carrier-Grade NAT)

### Purpose & Role
Manages large-scale Network Address Translation, enabling multiple subscribers to share IPv4 addresses while maintaining session state and logging for regulatory compliance.

### Key Interfaces
- **Input**: Packets from subscribers or upstream
- **Output**: Translated packets with new addressing
- **Control**: Address pool management, subscriber limits
- **Monitoring**: NAT session statistics, logging

### 3.1 NAT Translation Engine Sub-Module

#### Translation States
```c
struct nat_session {
    // Original (Internal) Side
    struct {
        uint32_t ip;                // Subscriber IP
        uint16_t port;              // Subscriber port
    } internal;

    // Translated (External) Side
    struct {
        uint32_t ip;                // ISP's public IP
        uint16_t port;              // Allocated port
    } external;

    // Session Info
    uint8_t protocol;               // TCP, UDP, etc.
    enum { NEW, ACTIVE, CLOSING, CLOSED } state;
    time_t creation_time;
    time_t last_activity;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t subscriber_id;
};
```

#### SNAT44 (Source NAT)
```
Outbound (Subscriber → Internet):
1. Receive packet from subscriber IP
2. Lookup or allocate external IP/port pair
3. Replace source IP with external IP
4. Replace source port with allocated port
5. Recalculate IP/TCP/UDP checksums
6. Forward packet

Inbound (Internet → Subscriber):
1. Receive packet destined for external IP/port
2. Lookup NAT session entry
3. Replace destination IP with subscriber IP
4. Replace destination port with subscriber port
5. Recalculate checksums
6. Forward to subscriber
```

#### DNAT44 (Destination NAT)
```
Inbound port forwarding:
1. Configure static mapping: external_ip:port → internal_ip:port
2. Receive incoming packets on external address
3. Translate destination IP/port to internal
4. Forward to internal service
```

### 3.2 Port Allocator Sub-Module

#### Port Pool Management
```c
struct port_pool {
    uint32_t start_port;
    uint32_t end_port;
    uint32_t current_port;          // Round-robin pointer
    uint32_t *allocation_map;       // Bitmap of allocated ports
    uint32_t allocated_count;
};

uint16_t allocate_port(struct nat_pool *pool) {
    // Find next available port using round-robin
    while (port_is_allocated(pool, pool->current_port)) {
        pool->current_port++;
        if (pool->current_port > pool->end_port)
            pool->current_port = pool->start_port;
    }

    mark_port_allocated(pool, pool->current_port);
    return pool->current_port++;
}
```

#### Allocation Strategies
1. **Round-Robin**: Sequential port allocation
2. **Random**: Random port selection (less predictable)
3. **Hash-Based**: Hash subscriber IP to port (deterministic)
4. **Port Overloading**: Allow multiple subscribers per external IP

#### Port Recycling
- Immediately recycle ports from closed connections
- Configurable TIME_WAIT period before reuse (prevents packet confusion)
- Per-subscriber port limits

### 3.3 Session Logger Sub-Module

#### Logging Requirements
- **5-Tuple Logging**: src_ip, dst_ip, src_port, dst_port, protocol
- **Translation Info**: external_ip, external_port
- **Session Lifecycle**: start_time, end_time, duration
- **Data Volume**: bytes_sent, bytes_received
- **Subscriber ID**: Link to billing/user

#### Log Export Formats
1. **IPFIX** (IP Flow Information Export)
   - RFC 7011 compliant
   - Structured binary format
   - Efficient storage

2. **NetFlow v5/v9**
   - Legacy but widely supported
   - Flow records with templates

3. **Syslog**
   - Standard log format
   - Real-time or batch export

#### Regulatory Compliance
```c
struct nat_log_entry {
    time_t session_start;           // Start time (UTC)
    time_t session_end;             // End time (UTC)
    uint32_t subscriber_ip;         // Private IP
    uint32_t external_ip;           // Public IP
    uint16_t subscriber_port;       // Private port
    uint16_t external_port;         // Public port
    uint8_t protocol;               // TCP/UDP
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t subscriber_id;         // For billing/legal
};
```

### 3.4 IPv6 Coexistence Layer Sub-Module

#### Dual-Stack Support
```
IPv4 → (CGNAT) → Public IPv4
  ↓                   ↓
IPv6 (no NAT) → Public IPv6
```

#### IPv6 Configuration
```c
struct dual_stack_session {
    // IPv4 Part (with NAT)
    struct {
        struct in_addr private_ip;
        struct in_addr public_ip;
        uint16_t public_port;
    } ipv4_nat;

    // IPv6 Part (typically no NAT)
    struct {
        struct in6_addr private_ip;
        struct in6_addr public_prefix;
    } ipv6_direct;
};
```

#### NAT64 (if needed)
- IPv4 clients communicating with IPv6 servers
- Stateful translation layer
- Application Layer Gateway (ALG) for FTP, SIP

---

## 4. QoS Module (Quality of Service)

### Purpose & Role
Classifies traffic, enforces policies, shapes bandwidth, and ensures service levels through prioritization and rate limiting.

### Key Interfaces
- **Input**: All data plane packets
- **Output**: Packets with scheduling/drop decisions
- **Control**: QoS policy updates
- **Monitoring**: Per-class statistics, queue depths

### 4.1 Traffic Classifier Sub-Module

#### Classification Methods

**1. 5-Tuple Classification**
```c
struct flow_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};
```

**2. DSCP-Based Classification**
```c
// Differentiated Services Code Point
uint8_t get_dscp(struct packet *pkt) {
    struct iphdr *ip = (struct iphdr *)pkt->data;
    return (ip->tos >> 2);  // DSCP is upper 6 bits of TOS
}
```

**3. Deep Packet Inspection (DPI)**
```c
enum app_type {
    APP_HTTP,
    APP_HTTPS,
    APP_VIDEO_STREAMING,
    APP_VoIP,
    APP_GAMING,
    APP_P2P,
    APP_UNKNOWN
};

enum app_type classify_application(struct packet *pkt) {
    // Check port numbers
    if (pkt->dst_port == 80) return APP_HTTP;
    if (pkt->dst_port == 443) return APP_HTTPS;

    // Check packet signature
    if (packet_matches_pattern(pkt, NETFLIX_PATTERN))
        return APP_VIDEO_STREAMING;

    // Check protocol headers
    if (detect_rtcp_packets(pkt)) return APP_VoIP;

    return APP_UNKNOWN;
}
```

**4. VLAN-Based Classification**
```c
uint16_t get_traffic_class(struct packet *pkt) {
    uint16_t vlan_id = extract_vlan_id(pkt);

    // Map VLAN to traffic class
    // VLAN 100 → Video
    // VLAN 101 → VoIP
    // VLAN 102 → Data
    return vlan_to_class_map[vlan_id];
}
```

#### Classification Result
```c
struct traffic_classification {
    uint8_t class_id;               // Traffic class (0-7)
    uint8_t priority;               // Priority (0=lowest, 7=highest)
    uint32_t rate_limit_kbps;       // Applied rate limit
    uint8_t dscp_marking;           // DSCP to mark packet with
};
```

### 4.2 Scheduler Sub-Module

#### Scheduling Algorithms

**1. Strict Priority Queuing (SPQ)**
```
Process highest priority queue first, only process lower priority
when higher priority queues are empty.

Risk: Starvation of low-priority traffic

Queue 0 (VoIP) ─┐
Queue 1 (Video)─┼→ Scheduler → Out
Queue 2 (Data) ─┘
```

**2. Weighted Fair Queuing (WFQ)**
```
Allocate bandwidth proportionally based on weights.

Queue 0 (VoIP) ─ Weight: 5  (50%)
Queue 1 (Video)─ Weight: 3  (30%)
Queue 2 (Data) ─ Weight: 2  (20%)

Algorithm: Round-robin with packet counts weighted by class
```

**3. Hierarchical Queuing (H-QoS)**
```
Per-subscriber queue:
    Subscriber Queue
    ├─ VoIP (strict priority)
    ├─ Video (weighted)
    └─ Data (best effort)

Per-interface queue:
    Interface Queue
    ├─ Subscriber 1
    ├─ Subscriber 2
    └─ Subscriber N (each gets equal share)
```

### 4.3 Policer Engine Sub-Module

#### Token Bucket Policer
```c
struct policer {
    uint32_t rate_kbps;             // Rate limit (kilobits per second)
    uint32_t burst_size_bytes;      // Maximum burst
    uint32_t current_tokens;
    time_t last_update;

    // Actions for rate exceeded
    enum { DROP, MARK_RED, MARK_YELLOW } action;
};

enum packet_color rate_limit_check(struct policer *p,
                                    uint32_t packet_size_bytes) {
    time_t now = current_time();

    // Convert rate from kbps to bytes
    uint32_t rate_bytes_per_sec = p->rate_kbps * 1000 / 8;

    // Calculate elapsed time and refill tokens
    time_t elapsed = now - p->last_update;
    uint32_t new_tokens = elapsed * rate_bytes_per_sec;
    p->current_tokens = MIN(p->burst_size_bytes,
                            p->current_tokens + new_tokens);
    p->last_update = now;

    if (p->current_tokens >= packet_size_bytes) {
        p->current_tokens -= packet_size_bytes;
        return GREEN;  // Within rate
    }
    return RED;        // Exceeds rate
}
```

#### Per-Subscriber Policing
```
Each subscriber has individual policer:
- Ingress rate limit (from subscriber)
- Egress rate limit (to subscriber)
- Burst allowance
```

### 4.4 Shaper Engine Sub-Module

#### Traffic Shaping
```
Token Bucket Shaper (delays packets rather than dropping):

Outgoing queue:
- Packet arrives
- Check tokens
- If tokens available: transmit immediately
- If no tokens: queue packet, wait for tokens to arrive
- Transmit when tokens available
```

#### Leaky Bucket Algorithm
```c
struct shaper {
    uint32_t rate_kbps;
    uint32_t queue_max_bytes;
    uint8_t *queue_buffer;          // Queued packets
    uint32_t queue_current_bytes;
    time_t last_drain_time;
};

int shape_packet(struct shaper *s, struct packet *pkt) {
    uint32_t pkt_bytes = pkt->len;

    // Check if queue is full
    if (s->queue_current_bytes + pkt_bytes > s->queue_max_bytes) {
        drop_packet(pkt);
        return -1;  // Dropped
    }

    // Enqueue packet
    enqueue(s->queue_buffer, pkt);
    s->queue_current_bytes += pkt_bytes;

    // Drain tokens and transmit from queue
    uint32_t rate_bytes_per_sec = s->rate_kbps * 1000 / 8;
    time_t elapsed = current_time() - s->last_drain_time;
    uint32_t bytes_to_drain = elapsed * rate_bytes_per_sec;

    while (bytes_to_drain > 0 && queue_not_empty(s->queue_buffer)) {
        struct packet *queued = dequeue(s->queue_buffer);
        transmit(queued);
        bytes_to_drain -= queued->len;
        s->queue_current_bytes -= queued->len;
    }

    return 0;  // Queued for later transmission
}
```

---

## 5. Routing Module

### Purpose & Role
Handles IP packet forwarding, maintains routing tables, manages BGP peering, and implements routing protocols.

### Key Interfaces
- **Input**: Packets requiring routing decisions
- **Output**: Forwarding decisions (next-hop interface)
- **Control**: Route management, BGP configuration
- **Monitoring**: Route statistics, BGP state

### 5.1 Forwarding Engine Sub-Module

#### Fast Path Forwarding
```c
// Optimized for speed - used for most packets
struct forwarding_entry {
    uint32_t dst_ip;
    uint32_t prefix_len;
    uint32_t next_hop_ip;
    uint32_t egress_interface;
    struct mac_entry *dst_mac;      // Cached ARP entry
};

// Packet forwarding
uint32_t get_egress_interface(struct packet *pkt) {
    struct iphdr *ip = (struct iphdr *)pkt->data;

    // Longest prefix match in routing table
    struct forwarding_entry *entry =
        lpm_lookup(routing_table, ip->daddr);

    if (entry == NULL) {
        // No route - send ICMP unreachable
        send_icmp_unreachable(pkt);
        return -1;
    }

    // Decrement TTL
    ip->ttl--;
    if (ip->ttl == 0) {
        send_icmp_time_exceeded(pkt);
        return -1;
    }

    // Recalculate checksum (TTL changed)
    ip->check = calculate_checksum(ip);

    // Add ARP information (MAC lookup)
    struct mac_entry *mac = get_mac_address(entry->next_hop_ip);
    add_ethernet_header(pkt, mac->src_mac, mac->dst_mac);

    return entry->egress_interface;
}
```

#### Longest Prefix Match (LPM)
```c
// Implemented as Radix Tree (Trie)
struct radix_node {
    uint32_t prefix;
    uint8_t prefix_len;
    struct radix_node *left;        // 0 bit
    struct radix_node *right;       // 1 bit
    struct forwarding_entry *data;
};

struct forwarding_entry *lpm_lookup(struct radix_tree *tree,
                                     uint32_t ip_address) {
    struct radix_node *node = tree->root;
    struct forwarding_entry *best_match = NULL;

    for (int i = 31; i >= 0; i--) {
        if (node == NULL) break;

        if (node->data != NULL) {
            best_match = node->data;  // Update best match
        }

        // Navigate tree based on bit at position i
        int bit = (ip_address >> i) & 1;
        node = bit ? node->right : node->left;
    }

    return best_match;
}
```

### 5.2 Routing Table Manager Sub-Module

#### RIB vs FIB
```
RIB (Routing Information Base): All routes from protocols
FIB (Forwarding Information Base): Selected routes for actual forwarding

RIB:
- BGP: 10.0.0.0/8 via 192.168.1.1
- Static: 10.0.0.0/8 via 192.168.1.2
- OSPF: 10.0.0.0/8 via 192.168.1.3

FIB (selected by admin/protocol preference):
- 10.0.0.0/8 via 192.168.1.1 (BGP, Admin distance 20)
```

#### Route Updates
```c
int add_route(struct routing_table *table,
              uint32_t prefix, uint8_t prefix_len,
              uint32_t next_hop, uint32_t egress_ifindex,
              uint8_t admin_distance, const char *source) {

    struct route_entry *entry = malloc(sizeof(*entry));
    entry->prefix = prefix;
    entry->prefix_len = prefix_len;
    entry->next_hop = next_hop;
    entry->egress_ifindex = egress_ifindex;
    entry->admin_distance = admin_distance;
    entry->source = strdup(source);
    entry->created_time = time(NULL);

    // Insert into RIB
    radix_tree_insert(table->rib, entry);

    // Update FIB if this is the best route
    if (is_best_route(table, prefix, prefix_len, entry)) {
        update_fib(table, prefix, prefix_len, entry);
    }

    // Announce if configured
    if (entry->source_protocol == PROTOCOL_STATIC) {
        bgp_announce_route(entry);
    }

    return 0;
}
```

### 5.3 BGP Engine Sub-Module

#### BGP Session Management
```c
struct bgp_peer {
    uint32_t peer_ip;
    uint16_t peer_asn;
    uint16_t local_asn;
    enum { IDLE, CONNECT, ACTIVE, OPENSENT, OPENCONFIRM, ESTABLISHED } state;

    // Timers
    uint32_t connect_retry_timer;
    uint32_t hold_time;
    uint32_t keepalive_interval;

    // Capabilities
    bool multiprotocol_ipv6;
    bool route_refresh;

    // Statistics
    uint32_t messages_sent;
    uint32_t messages_received;
    uint32_t routes_advertised;
    uint32_t routes_received;
};
```

#### BGP Packet Types
1. **OPEN** - Establish BGP session
2. **KEEPALIVE** - Maintain session
3. **UPDATE** - Announce/withdraw routes
4. **NOTIFICATION** - Error notification

#### Route Advertisement
```c
void bgp_advertise_route(struct bgp_peer *peer,
                        uint32_t prefix, uint8_t prefix_len,
                        struct bgp_attributes *attrs) {

    struct bgp_nlri *nlri = malloc(sizeof(*nlri));
    nlri->prefix = prefix;
    nlri->prefix_len = prefix_len;

    // Build UPDATE message with route
    struct bgp_update *update = build_bgp_update(nlri, attrs);

    // Send to peer
    bgp_send_update(peer, update);

    // Track route
    add_to_advertised_routes(peer, nlri);
}
```

### 5.4 Neighbor/ARP Manager Sub-Module

#### ARP Resolution
```c
struct arp_entry {
    uint32_t ip_address;
    uint8_t mac_address[6];
    time_t last_seen;
    uint8_t state;                  // VALID, STALE, INCOMPLETE
};

void send_arp_request(uint32_t target_ip, uint32_t source_ip,
                      uint8_t *source_mac, uint32_t ifindex) {
    struct arp_packet {
        uint16_t hardware_type;     // Ethernet = 1
        uint16_t protocol_type;     // IPv4 = 0x0800
        uint8_t hlen;               // 6 for MAC
        uint8_t plen;               // 4 for IPv4
        uint16_t operation;         // 1=Request, 2=Reply
        uint8_t sender_mac[6];
        uint32_t sender_ip;
        uint8_t target_mac[6];      // All zeros in request
        uint32_t target_ip;
    };

    // Fill in fields
    // Broadcast on network
}

void process_arp_reply(struct arp_packet *reply) {
    // Add entry to ARP table
    struct arp_entry *entry = malloc(sizeof(*entry));
    entry->ip_address = reply->sender_ip;
    memcpy(entry->mac_address, reply->sender_mac, 6);
    entry->last_seen = time(NULL);
    entry->state = VALID;

    // Insert into hash table
    arp_table_insert(entry);

    // Wake up any waiting packets
    notify_waiters_for_ip(reply->sender_ip);
}
```

---

## 6. Data Plane Module

### Purpose & Role
Core packet processing infrastructure utilizing DPDK for high-performance, zero-copy operations.

### 6.1 Packet Buffer Manager Sub-Module

#### DPDK Memory Pools
```c
struct rte_mempool {
    char name[RTE_MEMPOOL_NAMESIZE];
    void *pool_data;
    uint32_t nb_mem_chunks;
    size_t elt_size;                // Size of each element (mbuf)
    uint32_t trailer_size;
    uint32_t private_data_size;
    uint32_t nb_mbufs;
    uint64_t flags;

    // Statistics
    uint64_t put_count;
    uint64_t get_count;
};

// Allocate mbuf from pool
struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pool);

// Access packet data
uint8_t *packet_data = rte_pktmbuf_mtod(pkt, uint8_t *);
uint16_t packet_length = pkt->pkt_len;

// Free mbuf back to pool
rte_pktmbuf_free(pkt);
```

#### Ring Buffer (Lock-Free Queue)
```c
struct rte_ring {
    char name[RTE_RING_NAMESIZE];
    int flags;
    uint32_t size;                  // Number of elements
    uint32_t mask;                  // (size - 1)

    // Producer/consumer indexes (atomic)
    struct prod {
        uint32_t watermark;
        uint32_t sp_enqueue;        // Single producer flag
        uint32_t size_mask;
    } prod;

    struct cons {
        uint32_t sc_dequeue;        // Single consumer flag
        uint32_t size_mask;
    } cons;

    void *ring[0];                  // Actual ring buffer
};

// Enqueue packets (multiple producers)
int rte_ring_mp_enqueue_bulk(struct rte_ring *r,
                              void * const *obj_table,
                              uint32_t n) {
    // Atomically add objects to ring
}

// Dequeue packets (multiple consumers)
int rte_ring_mc_dequeue_bulk(struct rte_ring *r,
                              void **obj_table,
                              uint32_t n) {
    // Atomically remove objects from ring
}
```

### 6.2 CPU Scheduler Sub-Module

#### Thread/Core Affinity
```c
// Pin thread to CPU core
cpu_set_t cpuset;
CPU_ZERO(&cpuset);
CPU_SET(2, &cpuset);                // Pin to core 2
pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);

// Verify affinity
pthread_getaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
for (int i = 0; i < CPU_SETSIZE; i++) {
    if (CPU_ISSET(i, &cpuset)) {
        printf("Core %d assigned\n", i);
    }
}
```

#### Multi-Queue RX/TX (Multi-Queue NICs)
```
Physical NIC:
├─ Queue 0 → Core 0
├─ Queue 1 → Core 1
├─ Queue 2 → Core 2
└─ Queue 3 → Core 3

Each core processes its own queue without contention
```

### 6.3 Performance Tuning Sub-Module

#### NUMA Awareness
```c
// Allocate memory close to CPU running the thread
int numa_node = rte_lcore_to_socket_id(lcore_id);
struct rte_mempool *pool = rte_pktmbuf_pool_create(
    "pkt_pool", nb_mbufs, MBUF_CACHE_SIZE, 0,
    RTE_MBUF_DEFAULT_BUF_SIZE, numa_node);

// Access statistics from same NUMA node
struct rte_eth_stats stats;
rte_eth_stats_get(port_id, &stats);
```

#### Huge Pages
```bash
# Reserve 2GB of 2MB huge pages
echo 1024 > /proc/sys/vm/nr_hugepages

# Or 1GB huge pages
echo 2 > /proc/sys/vm/nr_hugepages_1g
```

Benefits:
- Reduced TLB misses
- Better cache efficiency
- Lower memory latency

---

## 7. Management Module

### Purpose & Role
Provides system management, configuration, monitoring, logging, and external API interfaces.

### 7.1 Configuration Manager Sub-Module

#### Configuration Hierarchy
```
Default Config
├── System Config (loaded on startup)
├── Interface Config
├── Routing Config
├── Service Config (BNG, Firewall, QoS, etc.)
└── User Overrides (runtime modifications)
```

#### Configuration File Format (YANG Model)
```yang
module yesrouter {
    namespace "http://yesrouter.com/ns/yesrouter";
    prefix br;

    container system {
        leaf hostname { type string; }
        leaf timezone { type string; }
    }

    container interfaces {
        list interface {
            key "name";
            leaf name { type string; }
            leaf enabled { type boolean; default true; }
            leaf mtu { type uint16; default 1500; }
        }
    }

    container routing {
        list route {
            key "destination";
            leaf destination { type string; }  // CIDR notation
            leaf next-hop { type string; }
            leaf distance { type uint8; }
        }
    }
}
```

### 7.2 Monitoring Engine Sub-Module

#### Statistics Collection
```c
struct interface_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_errors;
    uint64_t rx_dropped;

    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_dropped;
};

struct session_stats {
    uint32_t active_sessions;
    uint32_t session_setup_rate;    // per second
    uint64_t total_sessions;
    uint32_t ppp_sessions;
    uint32_t dhcp_sessions;
};
```

#### Real-time Dashboards
- Interface throughput (rx/tx)
- Active sessions
- CPU/memory utilization
- Top talkers
- Error rates
- QoS queue depths

### 7.3 Logging System Sub-Module

#### Log Levels
```
TRACE    (0) - Very detailed, function entry/exit
DEBUG    (1) - Debug information
INFO     (2) - Informational messages
WARNING  (3) - Warning conditions
ERROR    (4) - Error conditions
CRITICAL (5) - Critical failures
```

#### Log Destinations
```c
#define LOG_FILE    "/var/log/yesrouter/router.log"
#define LOG_SYSLOG  "local0"
#define LOG_CONSOLE "/dev/console"

// Example log line
2024-12-03T14:23:45Z [INFO]  Session 12345 established: PPPoE, IP=192.168.1.100, User=john@isp.com
2024-12-03T14:23:50Z [WARN]  Interface ge-0/0/0: link flapped
2024-12-03T14:24:00Z [ERROR] BGP peer 10.0.0.1 connection refused
```

### 7.4 API Layer Sub-Module

#### REST API Example
```
GET /api/v1/interfaces
  → Returns list of all interfaces

GET /api/v1/interfaces/ge-0-0-0/stats
  → Returns statistics for interface ge-0-0-0

GET /api/v1/sessions/active
  → Returns count of active subscriber sessions

POST /api/v1/sessions/{session-id}/terminate
  → Terminates specific session

PUT /api/v1/config/routing/routes
  → Updates routing table

GET /api/v1/metrics/cpu-usage
  → Returns system CPU utilization
```

#### Authentication
```c
// Token-based authentication
GET /api/v1/interfaces
Headers:
  Authorization: Bearer <JWT_TOKEN>
  X-API-Version: 1

// JWT contains user ID, permissions, expiration
```

---

## Summary

This document provides comprehensive module breakdowns for YESRouter. Each module is designed for high performance, scalability, and maintainability. The modular architecture enables:

- **Independent Testing**: Each module can be tested in isolation
- **Easy Upgrades**: Update individual modules without full system rebuild
- **Clear Responsibilities**: Well-defined interfaces between modules
- **Performance Optimization**: Focus optimization efforts on critical paths
- **Team Development**: Multiple teams can work on different modules in parallel
