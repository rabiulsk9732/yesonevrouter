# NAT Improvement #001: Per-Worker Session Tables (Lockless)

## Objective
Implement per-worker session tables to eliminate lock contention and improve NAT performance by 10-50x.

## Current Problem
- Multiple RX threads contend for same hash bucket locks
- Lock contention causes packet drops under high load
- Shared session tables create bottlenecks

## Solution
- Each worker thread has its own session table
- Sessions assigned to workers based on flow hash
- Lockless operation within each worker
- Cross-worker access only for session creation/deletion

## Implementation Plan

### Step 1: Activate Per-Worker Infrastructure
- Remove `__attribute__((unused))` from `g_nat_workers[]`
- Initialize worker tables in `nat_session_init()`
- Get worker ID from thread-local storage or flow hash

### Step 2: Modify Session Lookup
- `nat_session_lookup_inside()`: Use worker's table
- `nat_session_lookup_outside()`: Use worker's table
- Get worker ID from thread context

### Step 3: Modify Session Creation
- Assign session to worker based on flow hash
- Insert into worker's table (lockless)
- Also insert into global table for cross-worker access (with lock)

### Step 4: Testing
- Unit test: Verify sessions assigned correctly
- Performance test: Measure lock contention reduction
- Functional test: Verify NAT still works correctly

## Test Cases

### Test 1: Session Assignment
- Create 1000 sessions from different workers
- Verify sessions distributed across workers
- Verify each worker can find its own sessions

### Test 2: Lock Contention
- Run flood ping from multiple clients
- Measure lock wait time (should be near zero)
- Compare with old implementation

### Test 3: Functional Correctness
- Verify SNAT/DNAT still works
- Verify session lookup finds correct sessions
- Verify session deletion works

## Files to Modify
- `src/nat/nat_session.c` - Main implementation
- `src/forwarding/packet_rx.c` - Pass worker ID to NAT functions
- `include/nat.h` - Add worker ID parameter to lookup functions
- `tests/test_nat_worker.c` - New test file

## Success Criteria
- Zero lock contention in per-worker lookups
- 10x+ throughput improvement under load
- All existing tests pass
- No functional regressions
