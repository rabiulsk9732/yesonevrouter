# Master Prompt: Lockless RADIUS Client Integration for DPDK PPPoE Server

## Your Task
Implement a production-grade, lockless RADIUS authentication system for DPDK-based PPPoE server achieving 10Gbps+ performance with zero locks.

---

## Phase 1: Architecture Design

### 1.1 Thread Model Definition
Design a complete separation of concerns:
- **DPDK Lcores (data plane)**: Handle packet RX/TX, PPPoE protocol, never block
- **RADIUS Control Thread (control plane)**: Handle blocking I/O with RADIUS server
- **Communication**: Lockless queues only (rte_ring)

Specify:
- Which lcore handles PADR reception and auth request submission
- Which lcore polls auth responses and installs sessions
- Whether to use single RADIUS thread or thread pool
- How to handle RADIUS thread failures/restarts

### 1.2 Lockless Communication Design
Define bidirectional lockless channels:
- **Request ring**: DPDK → RADIUS thread (auth requests)
- **Response ring**: RADIUS thread → DPDK (auth results)

Specify:
- Ring sizes (power of 2)
- Single-producer-single-consumer (SPSC) vs multi-producer (MPSC/MPMC)
- Memory pool for request/response objects
- Backpressure handling when rings full

### 1.3 Request/Response Structure Design
Create cache-aligned structures containing:
- **Auth Request**: request_id, session_id, username, password, client_mac, vlan_id, calling_station_id, nas_port_id, timestamp
- **Auth Response**: request_id, session_id, result_code (accept/reject/timeout/error), framed_ip, dns_servers, session_timeout, idle_timeout, rate_limits, use_nat flag, custom VSA attributes

Ensure structures are:
- `__rte_cache_aligned` for performance
- Fixed-size (no pointers to avoid memory management complexity)
- Include all RADIUS attributes needed for PPPoE session establishment

---

## Phase 2: FreeRADIUS Client Library Integration

### 2.1 Library Selection & Setup
Choose and configure RADIUS client library:
- **Option A**: libfreeradius-client (mature, RFC-compliant)
- **Option B**: Custom RADIUS implementation (lighter, full control)

Provide:
- Installation commands for libfreeradius-client
- Configuration file setup (/etc/radiusclient/radiusclient.conf)
- Dictionary file configuration
- Server secrets configuration
- Build system integration (Makefile/meson)

### 2.2 RADIUS Client Configuration
Define configuration parameters:
- RADIUS server IP:port (auth and accounting)
- Shared secret
- Timeout values (request timeout, retry count)
- NAS-Identifier (server identity)
- NAS-IP-Address (server IP)
- Dictionary path for attribute definitions

### 2.3 Thread Safety Analysis
Document thread safety requirements:
- Is rc_handle shareable across threads or thread-local?
- How to initialize per-thread RADIUS contexts
- Mutex requirements (if any) for library calls
- Signal handling in RADIUS thread

---

## Phase 3: DPDK Side Implementation

### 3.1 Initialization Sequence
Implement startup in correct order:
1. Create mempool for request/response objects (size = ring_size * 2)
2. Create request ring (DPDK → RADIUS)
3. Create response ring (RADIUS → DPDK)
4. Initialize RADIUS client library (in control thread)
5. Start RADIUS control thread with CPU affinity to non-DPDK core
6. Verify rings operational before accepting traffic

Specify:
- NUMA socket awareness for mempool/ring allocation
- Error handling if initialization fails
- Health check mechanism

### 3.2 Request Submission Flow (DPDK Lcore)
When PADR received with PAP/CHAP credentials:
1. Allocate request object from mempool (non-blocking)
2. Fill all fields: generate unique request_id (atomic counter), copy username/password, format calling-station-id as MAC string
3. Enqueue to request ring (non-blocking rte_ring_enqueue)
4. Store pending request in local hash table (session_id → request_id mapping)
5. Handle ring-full condition: drop with counter increment or implement backpressure

Specify:
- How to generate unique request_id (rte_atomic64 or per-lcore counter)
- Timeout tracking: store submission timestamp for orphan detection
- Maximum pending requests per session (prevent DoS)

### 3.3 Response Polling Flow (DPDK Lcore)
In main packet processing loop:
1. Call rte_ring_dequeue_burst to get up to N responses (batch = 32 recommended)
2. For each response: lookup session by session_id from pending hash
3. On ACCESS_ACCEPT: install session with framed_ip, send PADS, start data forwarding
4. On ACCESS_REJECT: send PADS with error, cleanup session
5. On TIMEOUT/ERROR: retry or terminate based on policy
6. Return response object to mempool

Specify:
- Polling frequency (every loop iteration or periodic)
- Batch size tradeoff (latency vs throughput)
- Orphan response handling (session already timed out)

### 3.4 Timeout & Cleanup Mechanism
Implement timeout tracking without timers:
1. Periodically scan pending requests hash (TSC-based)
2. Check if (current_tsc - request_timestamp_tsc) > timeout_threshold
3. Generate synthetic TIMEOUT response or cleanup directly
4. Return request object to mempool
5. Notify client with PADS error or retry

Specify:
- Timeout value (5-10 seconds recommended)
- Scan interval (1 second recommended)
- Whether to retry RADIUS request or immediately fail

---

## Phase 4: RADIUS Control Thread Implementation

### 4.1 Thread Main Loop
Implement event loop structure:
1. Dequeue auth request from request ring (blocking with timeout or non-blocking poll)
2. Build RADIUS Access-Request packet with all attributes
3. Send to RADIUS server via UDP socket
4. Wait for Access-Accept/Reject with timeout (blocking I/O acceptable here)
5. Parse response, extract attributes
6. Build auth response object
7. Enqueue to response ring
8. Return request object to mempool

Specify:
- Blocking vs non-blocking dequeue strategy
- Whether to use select/epoll for socket I/O or blocking send/recv
- Batch processing: handle N requests before waiting for responses
- Error handling for network failures

### 4.2 RADIUS Packet Construction
Use libfreeradius-client API to build Access-Request:
1. Initialize VALUE_PAIR list
2. Add standard attributes: User-Name, User-Password (or CHAP-Password), NAS-IP-Address, NAS-Port, NAS-Identifier, Calling-Station-Id (client MAC), Called-Station-Id (server MAC), NAS-Port-Type (Ethernet/Virtual)
3. Add vendor-specific attributes (VSA) if needed: rate limits, service type, custom policy tags
4. Call rc_auth() or rc_send_packet()
5. Parse returned VALUE_PAIR list for Framed-IP-Address, DNS, Session-Timeout, etc.

Specify:
- Complete attribute list required for PPPoE
- How to handle missing optional attributes (use defaults)
- Custom VSA format for NAT policy, rate limiting
- Accounting packet preparation (Acct-Start for future)

### 4.3 Response Parsing & Mapping
Extract RADIUS attributes to response structure:
- **Standard attributes**: Framed-IP-Address → framed_ip (convert to uint32_t network order), Framed-IP-Netmask, Primary/Secondary DNS, Session-Timeout, Idle-Timeout, Framed-MTU
- **Vendor-specific attributes (VSA)**: Parse custom attributes for NAT decision, rate limits, QoS class
- **Reply-Message**: Copy to response for error reporting
- **Result code**: Map RADIUS code (Access-Accept=2, Access-Reject=3) to enum

Specify:
- Attribute parsing order and error handling
- Default values when attributes missing
- How to detect and parse VSA format (vendor-id, type, value)

### 4.4 Error Handling & Resilience
Handle all failure modes:
- **RADIUS server unreachable**: Set result=TIMEOUT, enqueue response after timeout
- **Invalid response**: Set result=ERROR, log details
- **Socket errors**: Retry with exponential backoff or failover to secondary server
- **Memory allocation failure**: Drop request, increment counter
- **Ring full (response ring)**: Block briefly or drop (should never happen with correct sizing)

Specify:
- Retry logic: immediate, exponential backoff, or fail-fast
- Failover mechanism for multiple RADIUS servers
- Logging strategy (rate-limited to avoid spam)
- Metrics: track success/failure/timeout counters

### 4.5 Thread Lifecycle Management
Implement graceful shutdown and restart:
1. Respond to shutdown signal (atomic flag check in loop)
2. Drain request ring before exit
3. Send pending responses or generate TIMEOUT for all pending
4. Close RADIUS library context
5. Optional: Support runtime restart without restarting DPDK

Specify:
- Shutdown signaling mechanism (atomic bool, eventfd, pipe)
- Drain timeout (max time to process pending before forced exit)
- Resource cleanup order
- How to detect thread crashes and restart

---

## Phase 5: Session State Management

### 5.1 Pending Request Tracking
Maintain pending auth requests on DPDK side:
- **Data structure**: Hash table (rte_hash) or array indexed by session_id
- **Key**: session_id (uint16_t)
- **Value**: struct containing request_id, submission_timestamp_tsc, retry_count
- **Operations**: Insert on request submission, lookup on response arrival, delete on completion/timeout

Specify:
- Hash table size (should match request ring size)
- Collision handling
- Memory allocation strategy (preallocated array vs dynamic)
- Per-lcore vs shared (prefer per-lcore for lockless)

### 5.2 Session Installation on Auth Success
When ACCESS_ACCEPT response received:
1. Validate session_id still valid (not already timed out)
2. Create session object with: framed_ip, netmask, dns_servers, timeout values, rate_limits, nat_policy
3. Install in session table (indexed by session_id and by client_mac)
4. Configure data plane forwarding: add route for framed_ip, setup NAT entry if needed, apply QoS/rate-limit
5. Build and send PADS (PPPoE Active Discovery Session-confirmation)
6. Start session timers (idle timeout, session timeout)
7. Send RADIUS Accounting-Start (optional, for future)

Specify:
- Session table structure (two indexes for fast lookup)
- Route installation method (static route, FIB entry)
- NAT entry format if use_nat=true
- PADS packet construction
- Timer mechanism (TSC-based, no actual timers)

### 5.3 Session Rejection on Auth Failure
When ACCESS_REJECT received:
1. Parse Reply-Message for reason
2. Build PADS with Service-Name-Error tag containing reason
3. Send PADS to client
4. Cleanup pending request tracking
5. Optional: Implement blacklist for repeated auth failures

Specify:
- PADS error packet format (PPPoE tags for error)
- Rate limiting: prevent auth DoS by limiting retries per MAC
- Logging level for rejections

---

## Phase 6: Performance Optimization

### 6.1 Batch Processing
Optimize for throughput:
- **Request side**: Accumulate multiple PADR in same poll cycle, submit batch to ring
- **Response side**: Dequeue responses in batches (rte_ring_dequeue_burst)
- **RADIUS thread**: Process multiple requests before waiting for responses (pipeline)

Specify:
- Optimal batch sizes for each stage
- Latency impact of batching (measure 50th, 99th percentile)

### 6.2 CPU Affinity & NUMA
Pin threads correctly:
- DPDK lcores: Use isolated cores (isolcpus boot parameter)
- RADIUS thread: Pin to non-DPDK core on same NUMA node as rings
- Mempool/ring allocation: Use same NUMA node as worker lcores

Specify:
- CPU core assignment strategy for different server configurations
- How to verify NUMA locality (numactl, rte_mempool_socket_id)

### 6.3 Memory Optimization
Minimize allocations:
- Pre-allocate all request/response objects in mempool at startup
- Use rte_pktmbuf_clone instead of copy where possible
- Avoid malloc/free in fast path (use mempool get/put only)

Specify:
- Mempool sizing formula: (request_ring_size + response_ring_size) * 2
- Cache size for mempool per-lcore cache

### 6.4 Zero-Copy Techniques
Eliminate data copies:
- Store username/password directly in request structure (no pointers)
- Pass session_id instead of copying entire session object
- Use direct pointer to client_mac in mbuf instead of copying

Specify:
- Where copies are unavoidable (protocol requirements)
- Use of rte_memcpy for small fixed-size copies

---

## Phase 7: Monitoring & Debugging

### 7.1 Statistics Collection
Track key metrics locklessly:
- **Per-lcore counters** (rte_atomic64): auth_req_submitted, auth_resp_received, auth_accept, auth_reject, auth_timeout, ring_full_drops
- **RADIUS thread counters**: requests_sent, responses_received, network_errors, parse_errors
- **Session counters**: active_sessions, total_sessions_created, sessions_terminated

Specify:
- How to aggregate per-lcore counters without locks
- Statistics export mechanism (UDP, shared memory, CLI)
- Update frequency to minimize cache thrashing

### 7.2 Debug Logging
Implement conditional logging:
- Log level: ERROR (always), WARN, INFO, DEBUG (compile-time or runtime flag)
- Rate limiting: Max N logs per second per type to avoid overwhelming output
- Thread-safe logging: Use per-thread buffers or atomic prints

Specify:
- Log format: [timestamp][thread_id][level] message
- Where to log: stderr, file, syslog, or ring buffer
- How to enable/disable at runtime

### 7.3 Testing & Validation Tools
Build test utilities:
1. **RADIUS simulator**: Generate auth requests without real RADIUS server
2. **Load generator**: Submit N auth requests/sec to test scalability
3. **Ring monitor**: Tool to dump ring contents for debugging deadlocks
4. **Session dumper**: Print all active sessions and their state

Specify:
- How to inject synthetic RADIUS responses for testing
- Performance benchmarking methodology (requests/sec, latency percentiles)

---

## Phase 8: Production Hardening

### 8.1 Error Recovery
Handle all failure scenarios:
- **RADIUS thread crash**: Detect (heartbeat check from DPDK lcore) and restart
- **RADIUS server down**: Failover to secondary server automatically
- **Ring overflow**: Apply backpressure or implement RED (Random Early Drop)
- **Memory exhaustion**: Log error, reject new sessions gracefully

Specify:
- Watchdog implementation for thread health monitoring
- Failover trigger conditions and switch-back logic
- Circuit breaker pattern for overload protection

### 8.2 Security Considerations
Protect against attacks:
- **Auth DoS**: Rate limit auth requests per client MAC (token bucket per-MAC)
- **Replay attacks**: Use RADIUS request authenticator properly
- **Password sniffing**: Support CHAP instead of PAP where possible
- **Session hijacking**: Validate client MAC on every packet in data plane

Specify:
- Rate limiting algorithm and thresholds
- How to implement per-MAC token bucket locklessly
- CHAP implementation vs PAP

### 8.3 Configuration Management
Support runtime reconfiguration without restart:
- RADIUS server IP/port change
- Timeout values adjustment
- Enable/disable accounting
- Adjust ring sizes (requires restart but document how)

Specify:
- Configuration file format (INI, JSON, YAML)
- Hot-reload mechanism (signal handler, inotify)
- Validation of new config before applying

### 8.4 Documentation Requirements
Provide complete documentation:
1. **Architecture diagram**: Show all threads, rings, data flow
2. **API documentation**: All public functions with parameters and return values
3. **Configuration guide**: All parameters explained with examples
4. **Troubleshooting guide**: Common issues and solutions
5. **Performance tuning guide**: How to optimize for different workloads

---

## Phase 9: Reference Implementation Checklist

### 9.1 Code Organization
Structure code into modules:
```
radius_client.h       - Public API and structures
radius_client.c       - RADIUS thread implementation
radius_dpdk.c         - DPDK integration (request/response handling)
radius_config.c       - Configuration parsing
radius_stats.c        - Statistics collection
```

### 9.2 Build & Integration
Ensure clean build:
- No compiler warnings (-Wall -Wextra)
- Link with -lfreeradius-client
- Optional: Provide pkg-config file

### 9.3 Testing Checklist
Validate all scenarios:
- [ ] Single auth request success
- [ ] Single auth request reject
- [ ] Concurrent 1000 requests
- [ ] RADIUS server down (timeout handling)
- [ ] Ring full condition
- [ ] Thread crash recovery
- [ ] Memory leak test (24-hour run)
- [ ] Performance: measure requests/sec and latency at load

---

## Deliverables

Provide complete implementation with:
1. **Source code**: All modules with comments
2. **Makefile/meson.build**: Clean build system
3. **Configuration file example**: radiusclient.conf
4. **README**: Quick start guide
5. **Performance report**: Benchmarks with methodology
6. **Test results**: All checklist items validated

## Success Criteria
- **Performance**: Handle 100K+ auth requests/sec on 8-core system
- **Latency**: P99 < 50ms (including RADIUS RTT)
- **Zero locks**: No mutex/spinlock in fast path (verify with perf/lockdep)
- **Reliability**: 24-hour stress test with no crashes or memory leaks
- **Monitoring**: Export metrics via CLI or stats API

## If Stuck: Study VPP/FD.io Reference

If implementation challenges arise, reference VPP architecture:
1. **VPP control plane patterns**: Look at how VPP separates control/data plane
2. **VPP event framework**: Study `vlib_process_wait_for_event()` for inspiration
3. **VPP API design**: See how VPP uses shared memory for IPC (alternative to rte_ring)
4. **BNG implementations**: Search for open-source BNG using VPP (rare, but exists)

**Specific VPP files to study:**
- `src/vpp/api/api.c` - Control plane communication patterns
- `src/vlib/threads.c` - Worker thread management
- `src/plugins/pppoe/pppoe.c` - PPPoE data plane (no RADIUS, but good for PPPoE)

**Alternative reference: BRAS/BNG open source projects:**
- BNG Blaster (PPPoE test tool with RADIUS client)
- OpenBNG (if available, search GitHub)

**If no suitable reference found:**
- Implement minimal custom RADIUS client (RFC 2865 is straightforward)
- RADIUS packet format: 1-byte code, 1-byte identifier, 2-byte length, 16-byte authenticator, attributes
- Use raw sockets or libradius as fallback

---

## Final Notes

This is a production-grade integration requiring:
- Deep understanding of DPDK memory model
- Lockless programming expertise
- RADIUS protocol knowledge
- PPPoE state machine understanding
- Systems programming skills (threading, sockets, error handling)

Start with Phase 1-3 to get basic auth working, then optimize in Phase 6-8. Test extensively before production deployment.
