# PPPoE and RADIUS Complete Implementation Tasklist

> **Legend**: ✅ = Implemented | ⚠️ = Partial | ❌ = Not Implemented | 🔧 = Needs Fix

---

## Phase 1: PPPoE Discovery Stage (RFC 2516)

### 1.1 PADI Handling

- [x] Parse PADI packet structure
- [x] Validate PPPoE version/type (must be 1/1)
- [x] Extract Service-Name tag
- [x] Extract Host-Uniq tag
- [x] Validate source MAC (not broadcast)
- [x] Rate limit PADI per source MAC (`pppoe_security.c`)
- [ ] Implement global PADI rate limit counter
- [ ] Add PADI flood detection alerting

### 1.2 PADO Generation

- [x] Build PADO response packet
- [x] Include AC-Name tag (`pppoe_set_ac_name()`)
- [x] Include Service-Name tag (`pppoe_set_service_name()`)
- [x] Echo Host-Uniq tag from PADI
- [x] Support PADO delay (`pppoe_set_pado_delay()`)
- [ ] Implement AC-Cookie generation for DoS prevention
- [ ] Add AC-Cookie validation in PADR
- [ ] Support multiple Service-Name offers

### 1.3 PADR Handling

- [x] Parse PADR packet structure
- [x] Validate Service-Name tag matches
- [x] Validate Host-Uniq tag
- [x] Allocate unique Session ID (1-65535)
- [x] Create session in hash table
- [ ] Validate AC-Cookie if present
- [ ] Implement session limit per MAC
- [ ] Add configurable max sessions per interface

### 1.4 PADS Generation

- [x] Build PADS response with assigned Session ID
- [x] Include Service-Name tag
- [x] Echo Host-Uniq tag
- [x] Handle VLAN tagging correctly
- [ ] Include AC-Cookie if used
- [ ] Support Service-Name-Error response

### 1.5 PADT Handling

- [x] Parse PADT packet
- [x] Match session by ID + MAC
- [x] Clean up session resources
- [x] Send PADT on server-initiated termination
- [ ] Log termination reason
- [ ] Trigger RADIUS Accounting-Stop

---

## Phase 2: PPP Link Control Protocol (LCP - RFC 1661)

### 2.1 LCP State Machine

- [x] Implement Initial state
- [x] Implement Starting state
- [x] Implement Closed state
- [x] Implement Stopped state
- [x] Implement Closing state
- [x] Implement Stopping state
- [x] Implement Req-Sent state
- [x] Implement Ack-Rcvd state
- [x] Implement Ack-Sent state
- [x] Implement Opened state
- [x] State transition on events (Up, Down, Open, Close)
- [ ] Full RFC 1661 compliance verification

### 2.2 LCP Configure-Request

- [x] Send Configure-Request
- [x] Include MRU option
- [x] Include Auth-Protocol option (PAP/CHAP)
- [x] Include Magic-Number option
- [x] Retry with timeout (`conf_req_retries`)
- [ ] Include Protocol-Field-Compression option
- [ ] Include Address-Control-Compression option
- [ ] Implement Configure-Request timeout backoff

### 2.3 LCP Configure-Ack/Nak/Reject

- [x] Send Configure-Ack for acceptable options
- [x] Parse received Configure-Ack
- [x] Send Configure-Nak with preferred values
- [x] Parse received Configure-Nak
- [x] Send Configure-Reject for unknown options
- [ ] Parse received Configure-Reject
- [ ] Handle option renegotiation loop detection

### 2.4 LCP Echo-Request/Reply (Keepalive)

- [x] Send Echo-Request periodically (`lcp_echo_interval`)
- [x] Process Echo-Reply and reset failure counter
- [x] Track echo failures (`echo_failures`)
- [x] Terminate session after max failures (`lcp_echo_failure`)
- [x] Include Magic-Number in echo

### 2.5 LCP Terminate

- [x] Send Terminate-Request
- [x] Process Terminate-Request
- [x] Send Terminate-Ack
- [x] Handle session cleanup on terminate

### 2.6 LCP Error Handling

- [ ] Implement Code-Reject
- [ ] Implement Protocol-Reject
- [ ] Handle unknown LCP codes gracefully
- [ ] Log LCP errors with session context

---

## Phase 3: PPP Authentication

### 3.1 PAP (RFC 1334)

- [x] Negotiate PAP in LCP Auth-Protocol
- [x] Parse PAP Authenticate-Request
- [x] Extract username and password
- [x] Send to RADIUS for authentication
- [x] Send PAP Authenticate-Ack on success
- [x] Send PAP Authenticate-Nak on failure
- [ ] Include message in Ack/Nak response
- [ ] Implement PAP timeout handling

### 3.2 CHAP (RFC 1994)

- [x] Negotiate CHAP in LCP Auth-Protocol
- [x] Generate random CHAP challenge (`chap_challenge[]`)
- [x] Send CHAP Challenge to client
- [x] Parse CHAP Response
- [x] Verify via RADIUS
- [x] Send CHAP Success on accept
- [x] Send CHAP Failure on reject
- [ ] Implement CHAP re-authentication
- [ ] Support multiple CHAP algorithms (MD5 vs MS-CHAP)

### 3.3 MS-CHAPv1 (RFC 2433)

- [x] NT Password Hash generation (`mschap_nt_password_hash()`)
- [x] DES encryption for response (`des_encrypt_block_simple()`)
- [x] Challenge-Response calculation
- [x] Response verification (`mschap_v1_verify()`)
- [x] RADIUS attribute formatting
- [ ] Proper DES-ECB via EVP (current is simplified)
- [ ] LM-Response support (legacy)

### 3.4 MS-CHAPv2 (RFC 2759)

- [x] Challenge hash generation (`mschap_v2_challenge_hash()`)
- [x] NT-Response generation (`mschap_v2_response()`)
- [x] Response verification (`mschap_v2_verify()`)
- [ ] Authenticator response generation (mutual auth)
- [ ] MPPE key derivation for encryption

### 3.5 EAP (Extensible Authentication Protocol)

- [ ] Implement EAP framework
- [ ] EAP-Identity request/response
- [ ] EAP-MD5 method
- [ ] EAP-TLS method (optional)
- [ ] EAP pass-through to RADIUS

---

## Phase 4: PPP Network Control Protocols

### 4.1 IPCP (RFC 1332)

- [x] Implement IPCP state machine
- [x] Send IPCP Configure-Request
- [x] Parse client IPCP Configure-Request
- [x] Negotiate IP-Address option
- [x] Assign IP from pool
- [x] Send Configure-Nak with assigned IP
- [x] Send Configure-Ack when client accepts
- [x] Assign Primary-DNS
- [x] Assign Secondary-DNS
- [ ] Implement IP-Compression-Protocol option
- [ ] Support static IP assignment from RADIUS
- [ ] NBNS server assignment (NetBIOS)

### 4.2 IPv6CP (RFC 5072)

- [ ] Implement IPv6CP state machine
- [ ] Interface-Identifier option negotiation
- [ ] Generate random Interface-ID for server
- [ ] Accept/propose client Interface-ID
- [ ] Link-local address configuration
- [ ] Integrate with DHCPv6-PD for prefix delegation
- [ ] RA (Router Advertisement) for SLAAC

### 4.3 CCP (Compression Control Protocol)

- [ ] Implement CCP negotiation (optional)
- [ ] Support MPPC compression (optional)
- [ ] Support MPPE encryption (optional)

---

## Phase 5: Session Management

### 5.1 Session Table Operations

- [x] Create session with unique ID (`pppoe_create_session()`)
- [x] O(1) lookup by Session-ID + MAC (`rte_hash`)
- [x] O(1) lookup by Client IP (`session_ip_hash`)
- [x] Session bitmap for ID allocation
- [x] Session cleanup on termination
- [ ] Per-worker session tables (full lockless)
- [ ] Session migration between workers
- [ ] Session export to backup node

### 5.2 Session Lifecycle

- [x] State: Initial → PADI_RCVD → PADR_RCVD → Established → Terminated
- [x] LCP state tracking
- [x] IPCP state tracking
- [x] Auth completion flag
- [x] Timestamp tracking (created, last_activity)
- [ ] Add IPv6CP state tracking
- [ ] Full state machine diagram in docs

### 5.3 Session Timeouts

- [x] Idle timeout (`idle_timeout`)
- [x] Session timeout (`session_timeout`)
- [x] LCP echo timeout handling
- [x] Periodic timeout check (`pppoe_check_keepalives()`)
- [ ] Configurable timeout per service profile
- [ ] Grace period before hard disconnect

### 5.4 Session Limits

- [ ] Max sessions per MAC address
- [ ] Max sessions per VLAN
- [ ] Max sessions per interface
- [ ] Global max sessions limit
- [ ] Session quota from RADIUS

---

## Phase 6: RADIUS Authentication (RFC 2865)

### 6.1 RADIUS Client Core

- [x] Lockless ring architecture (`radius_lockless.c`)
- [x] Request/Response ring buffers
- [x] Memory pool for requests
- [x] Control thread for I/O
- [x] Socket creation and binding
- [ ] UDP source port per request
- [ ] Request-Response matching by ID + Authenticator

### 6.2 Access-Request

- [x] Build Access-Request packet
- [x] User-Name attribute (type 1)
- [x] User-Password attribute (type 2, encrypted)
- [x] CHAP-Password attribute (type 3)
- [x] NAS-IP-Address attribute (type 4)
- [x] NAS-Port attribute (type 5)
- [x] Service-Type attribute (type 6)
- [x] Framed-Protocol attribute (type 7)
- [x] NAS-Identifier attribute (type 32)
- [x] Calling-Station-Id (MAC address)
- [ ] Called-Station-Id (access concentrator)
- [ ] NAS-Port-Type attribute
- [ ] NAS-Port-Id attribute
- [ ] Framed-MTU attribute

### 6.3 Access-Accept Processing

- [x] Parse Access-Accept response
- [x] Extract Framed-IP-Address (type 8)
- [x] Extract Session-Timeout (type 27)
- [x] Extract Idle-Timeout (type 28)
- [ ] Extract Framed-IP-Netmask (type 9)
- [ ] Extract Framed-Route (type 22)
- [ ] Extract Filter-Id (type 11)
- [ ] Extract Class attribute (type 25) - save for accounting
- [ ] Extract Reply-Message (type 18)
- [ ] Parse Vendor-Specific Attributes (type 26)

### 6.4 Access-Reject Processing

- [x] Detect Access-Reject response
- [x] Deny authentication
- [ ] Parse Reply-Message for error reason
- [ ] Log reject reason

### 6.5 Access-Challenge (CHAP/EAP)

- [ ] Detect Access-Challenge response
- [ ] Pass challenge data to PPP layer
- [ ] Support multi-round authentication
- [ ] EAP message attribute handling

### 6.6 Server Management

- [x] Multiple server support (up to 8)
- [x] Priority-based server selection
- [x] Server failover on timeout
- [x] Configurable timeout (`timeout_ms`)
- [x] Configurable retries (`max_retries`)
- [ ] Server health monitoring
- [ ] Dead server detection
- [ ] Server weight for load balancing

---

## Phase 7: RADIUS Accounting (RFC 2866) — CRITICAL

> ⚠️ **Current Status**: Stub only - NOT IMPLEMENTED

### 7.1 Accounting-Request Core

- [ ] Create accounting request structure
- [ ] Accounting ring buffer (separate from auth)
- [ ] Accounting socket (port 1813 default)
- [ ] Request ID management
- [ ] Authenticator calculation

### 7.2 Accounting-Start (Status-Type = 1)

- [ ] Trigger on session establishment (post-IPCP)
- [ ] Acct-Status-Type = Start (1)
- [ ] Acct-Session-Id (unique string)
- [ ] User-Name attribute
- [ ] NAS-IP-Address
- [ ] NAS-Port
- [ ] Framed-IP-Address
- [ ] Acct-Authentic (RADIUS=1, Local=2)
- [ ] Event-Timestamp
- [ ] Class attribute (from Access-Accept)

### 7.3 Accounting-Interim (Status-Type = 3)

- [ ] Periodic interim updates (`acct_interim_interval`)
- [ ] Acct-Status-Type = Interim-Update (3)
- [ ] Acct-Session-Time (duration in seconds)
- [ ] Acct-Input-Octets (bytes from client)
- [ ] Acct-Output-Octets (bytes to client)
- [ ] Acct-Input-Packets
- [ ] Acct-Output-Packets
- [ ] Handle 32-bit counter overflow
- [ ] Acct-Input-Gigawords (high 32 bits)
- [ ] Acct-Output-Gigawords (high 32 bits)

### 7.4 Accounting-Stop (Status-Type = 2)

- [ ] Trigger on session termination
- [ ] Acct-Status-Type = Stop (2)
- [ ] All interim attributes plus:
- [ ] Acct-Terminate-Cause
- [ ] Final counters
- [ ] Handle: User-Request (1), Lost-Carrier (2), Lost-Service (3), Idle-Timeout (4), Session-Timeout (5), Admin-Reset (6), NAS-Error (9), NAS-Reboot (11)

### 7.5 Accounting Reliability

- [ ] Store-and-forward on server failure
- [ ] Retry accounting requests
- [ ] Accounting-Response validation
- [ ] Duplicate detection (Acct-Delay-Time)
- [ ] Accounting server failover
- [ ] Offline accounting storage (optional)

---

## Phase 8: RADIUS CoA/DM (RFC 5176)

### 8.1 CoA (Change of Authorization)

- [ ] Listen on UDP port 3799
- [ ] Parse CoA-Request
- [ ] Match session by User-Name or Acct-Session-Id
- [ ] Apply new Session-Timeout
- [ ] Apply new Filter-Id (ACL)
- [ ] Apply new rate limits
- [ ] Send CoA-ACK on success
- [ ] Send CoA-NAK on failure with Error-Cause

### 8.2 Disconnect-Message

- [ ] Parse Disconnect-Request
- [ ] Match session
- [ ] Terminate session gracefully
- [ ] Send Disconnect-ACK
- [ ] Trigger Accounting-Stop
- [ ] Log disconnect reason

---

## Phase 9: QoS Integration

### 9.1 Per-Session Rate Limiting

- [x] Token bucket per session (`downlink_tb`)
- [x] CIR/MIR metering (`qos_meter_packet()`)
- [x] Burst handling (CBS/PBS)
- [x] Dynamic rate update (`qos_session_update_rates()`)
- [ ] Uplink token bucket in session struct
- [ ] Rate limits from RADIUS attributes
- [ ] Vendor-specific QoS attributes

### 9.2 RADIUS QoS Attributes

- [ ] Parse Mikrotik-Rate-Limit VSA
- [ ] Parse Cisco-AVPair for rate
- [ ] Parse WISPr-Bandwidth-Max-Down
- [ ] Parse WISPr-Bandwidth-Max-Up
- [ ] Apply limits post-authentication

---

## Phase 10: IPv6 Support for PPPoE

### 10.1 IPv6CP Protocol

- [ ] IPv6CP state machine
- [ ] Interface-ID negotiation
- [ ] Link-local address assignment
- [ ] Router Advertisement integration
- [ ] DHCPv6-PD integration for prefix delegation

### 10.2 Dual-Stack Sessions

- [ ] Track IPv4 and IPv6 state separately
- [ ] Allow IPv4-only, IPv6-only, or dual-stack
- [ ] Separate accounting for v4/v6 traffic

---

## Phase 11: High Availability

### 11.1 Session Synchronization

- [x] Session sync message format (`ha_sync_msg`)
- [x] Session create/update/delete sync
- [ ] Full session state replication
- [ ] Incremental sync on session change
- [ ] Bulk sync on failover

### 11.2 Active-Passive Failover

- [x] Heartbeat mechanism
- [x] Master/Backup state machine
- [x] VIP failover (`ha_set_vip()`)
- [ ] Seamless session takeover
- [ ] Accounting continuity on failover

### 11.3 Active-Active (Future)

- [ ] Session sharding across nodes
- [ ] Deterministic session placement
- [ ] Cross-node session lookup
- [ ] Load balancing strategy

---

## Phase 12: Security Hardening

### 12.1 DoS Protection

- [x] PADI rate limiting per MAC
- [x] Global PADI rate limit
- [ ] AC-Cookie mechanism
- [ ] SYN-cookie equivalent for PPPoE
- [ ] Blacklist persistent attackers

### 12.2 Session Security

- [x] MAC-Session binding
- [x] IP spoofing detection
- [x] Session hijack prevention
- [ ] Max sessions per MAC
- [ ] Authentication rate limiting

### 12.3 RADIUS Security

- [x] Shared secret encryption
- [x] Authenticator validation
- [ ] RADIUS over TLS (RadSec)
- [ ] Secret rotation support

---

## Phase 13: Monitoring & Statistics

### 13.1 Session Statistics

- [x] Active session count
- [x] Per-session packet/byte counters
- [x] Session creation/deletion counts
- [ ] Session setup rate (sessions/sec)
- [ ] Average session duration
- [ ] Peak concurrent sessions

### 13.2 RADIUS Statistics

- [x] Requests submitted
- [x] Requests sent
- [x] Responses received
- [x] Accepts/Rejects count
- [x] Timeouts count
- [ ] Average response time
- [ ] Per-server statistics

### 13.3 Protocol Statistics

- [ ] LCP negotiations started/completed
- [ ] Authentication success/failure rate
- [ ] IPCP assignments
- [ ] IPv6CP assignments
- [ ] Protocol error counts

---

## Phase 14: Testing & Validation

### 14.1 Unit Tests

- [x] Session create/lookup test
- [x] Token bucket test
- [x] IP pool test
- [x] LCP state test
- [x] RADIUS packet format test
- [ ] Full IPCP negotiation test
- [ ] IPv6CP test
- [ ] Accounting packet test

### 14.2 Integration Tests

- [x] RADIUS server integration test
- [ ] Full PPPoE session test (PADI→PADS→LCP→Auth→IPCP)
- [ ] Multi-session concurrency test
- [ ] Failover test
- [ ] Accounting accuracy test

### 14.3 Performance Tests

- [ ] Session setup rate benchmark (target: 10K/sec)
- [ ] Concurrent sessions benchmark (target: 100K+)
- [ ] Data plane throughput (target: 10Gbps)
- [ ] Memory usage per session
- [ ] CPU usage under load

### 14.4 Compliance Tests

- [ ] RFC 2516 (PPPoE) compliance
- [ ] RFC 1661 (PPP) compliance
- [ ] RFC 1994 (CHAP) compliance
- [ ] RFC 2865 (RADIUS Auth) compliance
- [ ] RFC 2866 (RADIUS Acct) compliance

---

## Summary: Priority-Ordered Task Phases

| Phase                       | Priority          | Effort  | Status |
| --------------------------- | ----------------- | ------- | ------ |
| Phase 7: RADIUS Accounting  | **P0 - Critical** | 2 weeks | ❌ 10% |
| Phase 4.2: IPv6CP           | **P1 - High**     | 1 week  | ❌ 0%  |
| Phase 8: CoA/DM             | **P1 - High**     | 1 week  | ❌ 0%  |
| Phase 6.5: Access-Challenge | P2 - Medium       | 3 days  | ❌ 0%  |
| Phase 3.5: EAP              | P2 - Medium       | 1 week  | ❌ 0%  |
| Phase 11: HA Completion     | P2 - Medium       | 1 week  | ⚠️ 50% |
| Phase 9.2: RADIUS QoS       | P3 - Low          | 3 days  | ❌ 0%  |
| Phase 14: Testing           | P3 - Low          | 2 weeks | ⚠️ 40% |

---

## Quick Reference: File Locations

| Component      | File                           | Lines |
| -------------- | ------------------------------ | ----- |
| PPPoE Core     | `src/pppoe/pppoe.c`            | 1725  |
| LCP Protocol   | `src/pppoe/ppp_lcp.c`          | 400   |
| IPCP Protocol  | `src/pppoe/ppp_ipcp.c`         | 349   |
| Authentication | `src/pppoe/ppp_auth.c`         | 272   |
| MS-CHAP        | `src/pppoe/mschap.c`           | 225   |
| Security       | `src/pppoe/pppoe_security.c`   | 270   |
| RADIUS Client  | `src/radius/radius_lockless.c` | 1045  |
| RADIUS Header  | `include/radius_lockless.h`    | 377   |
| QoS            | `src/qos/qos.c`                | 266   |
| HA             | `src/ha/ha.c`                  | 178   |
| Session Header | `include/pppoe.h`              | 277   |

---

_Generated: 2025-12-15_
