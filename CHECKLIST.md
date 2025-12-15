PRODUCTION-READY NAT44 (DPDK) — DEVELOPER CHECKLIST
0️⃣ Scope & Assumptions (LOCK THIS FIRST)

 Userspace NAT (DPDK only, no kernel fallback)

 Multi-core, multi-queue enabled (≥ 4 workers)

 Endpoint-Dependent (ED) NAT by default

 No single-worker mode allowed in production

 Lockless dataplane (no mutexes in fastpath)

If any of these are false → NOT production ready

1️⃣ Control-Plane → Dataplane Binding
Interface & Role Mapping

 Interface names in config match DPDK port names

 Exactly one or more nat_inside interfaces

 Exactly one or more nat_outside interfaces

 NAT hooks only run if interface role is explicitly set

 Clear error if no inside/outside interface configured

NAT Pools

 At least one public IP pool exists

 Pool IPs validated (not RFC1918)

 Pool initialized before workers start

 Worker-local port ranges derived from pool

 No overlapping port ranges between workers

2️⃣ Packet Classification (NON-NEGOTIABLE)

 Direction detection is correct:

inside → outside

outside → inside

 Hairpin traffic explicitly handled or dropped

 Packets never bypass NAT silently

 NAT entry point executed for every eligible packet

 Non-IPv4 traffic bypassed cleanly

3️⃣ Flow Ownership & Worker Model (CRITICAL)
Deterministic Ownership

 Flow → worker mapping is deterministic

 Hash uses inside tuple only:

inside IP

inside port / ICMP ID

protocol

 Hash result never changes after translation

Ownership Enforcement

 Ownership enforced BEFORE session lookup

 Ownership enforced BEFORE session creation

 Ownership enforced BEFORE SNAT/DNAT rewrite

 Non-owner worker NEVER rewrites packets

Handoff

 RX worker ≠ owner worker → packet handed off

 Handoff uses lockless mechanism (rte_ring)

 Handoff never silently drops established flows

 Handoff counters exposed (enqueue/dequeue/drop)

🚨 If packets are dropped due to worker mismatch → FAIL

4️⃣ Session Tables & State Management
Session Storage

 Session tables are per-worker

 No global session table

 No cross-worker session mutation

 Session struct includes:

owner worker

inside tuple

outside tuple

NAT IP/port

last activity timestamp

Session Lifecycle

 Session created ONLY on owner worker

 Session visible immediately after creation

 No duplicate session creation for same flow

 Session deletion frees port & memory

 Session timeout logic per protocol

5️⃣ NAT44 Translation Logic
SNAT (Inside → Outside)

 Source IP rewritten to public IP

 Source port / ICMP ID rewritten if required

 Checksums recomputed correctly

 Rewrite executed on every packet, not only first

 SNAT counters increment on owner worker only

DNAT (Outside → Inside)

 Reverse lookup uses translated tuple

 Owner worker determined from NAT port

 Packet handed off BEFORE lookup if needed

 Destination IP/port rewritten back

 DNAT counters increment on owner worker only

6️⃣ Endpoint-Dependent (ED) Filtering

 Session key includes original external endpoint

 Return traffic must match:

public IP

public port / ICMP ID

original destination IP

original destination port

 Unsolicited inbound traffic dropped

 ED drop counters exposed

 EI (full-cone) disabled unless explicitly configured

7️⃣ ICMP Handling (MANDATORY)
ICMP Echo

 ICMP identifier treated like a port

 Echo Request creates session

 Echo Reply matches same session

 ICMP checksum recomputed

ICMP Error / Traceroute (ALG)

 ICMP types 3, 4, 11, 12 handled

 Embedded IP header parsed

 Embedded tuple translated correctly

 Inner + outer checksums fixed

 ALG executed ONLY on owner worker

🚨 Traceroute must work end-to-end → otherwise FAIL

8️⃣ Multi-Worker Correctness Tests (REQUIRED)

 Sessions created on exactly one worker

 SNAT/DNAT counters move on same worker

 No duplicate sessions across workers

 No translation on non-owner worker

 XWorker Hit/Miss counters behave as expected

 No silent drops under RSS asymmetry

9️⃣ Backpressure & Drop Policy

 Ring-full drops are counted

 No silent packet drops

 Established flows protected from internal drops

 Clear logging when drops occur

 Drop reasons distinguishable (ring full, no session, no port)

🔟 Statistics & Observability
Mandatory Counters

 Sessions created / active / deleted / timed out

 SNAT packets

 DNAT packets

 Session miss

 ED drop

 Port allocation failure

 Handoff enqueue / dequeue / drop

CLI / API

 Per-worker stats visible

 Global aggregation correct

 Stats do not lie under multi-worker load

1️⃣1️⃣ Performance Safety (NOT BENCHMARKING)

 No locks in fastpath

 No malloc/free in fastpath

 Session lookup O(1)

 Cache hot path exists

 Packet rewrite touches minimal cache lines

1️⃣2️⃣ Failure & Abuse Scenarios

 NAT pool exhaustion handled cleanly

 Session table exhaustion handled cleanly

 Unsolicited inbound traffic dropped

 Invalid packets dropped safely

 No crash on malformed ICMP / TCP / UDP

1️⃣3️⃣ Deployment Readiness

 Works with virtio (dev)

 Works with hardware NIC (RSS)

 RSS asymmetry tolerated

 NUMA awareness validated

 Restart does not corrupt state

1️⃣4️⃣ Final GO / NO-GO Gate

You may ship ONLY if all are true:

 Ping works

 Traceroute works

 TCP downloads stable

 Multi-core enabled

 No silent drops

 Ownership enforced everywhere

 Stats trustworthy

If even one box is unchecked → DO NOT DEPLOY
