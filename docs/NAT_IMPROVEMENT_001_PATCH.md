# NAT Improvement #001: Per-Worker Session Tables - Patch

## Summary
Implemented Phase 1 infrastructure for per-worker session tables to enable lockless NAT lookups and eliminate lock contention.

## Changes

### Files Modified

#### 1. `include/cpu_scheduler.h`
- Added `g_thread_worker_id` thread-local variable declaration

#### 2. `src/core/cpu_scheduler.c`
- Added `g_thread_worker_id` thread-local variable definition

#### 3. `src/forwarding/packet_rx.c`
- Set `g_thread_worker_id` in RX thread based on worker_id
- Call `nat_set_num_workers()` when starting RX threads

#### 4. `src/nat/nat_session.c`
- Removed `__attribute__((unused))` from `g_nat_workers[]` and `g_num_workers`
- Initialize per-worker tables in `nat_session_init()`
- Modified `nat_session_lookup_inside()` to check per-worker table first (lockless)
- Added worker statistics tracking in session creation
- Fixed `get_worker_id()` to handle zero workers

#### 5. `src/nat/nat_worker.c` (NEW)
- Added `nat_set_num_workers()` function
- Added `nat_get_num_workers()` function
- Added `nat_get_worker_stats()` function

#### 6. `include/nat.h`
- Added function declarations for worker management

#### 7. `src/nat/CMakeLists.txt`
- Added `nat_worker.c` to build

#### 8. `tests/test_nat_worker.c` (NEW)
- Test worker ID assignment
- Test session creation with worker assignment
- Test per-worker statistics

## Implementation Details

### Phase 1 (Current)
- Infrastructure in place: thread-local worker_id, worker tables initialized
- Lookup checks per-worker table first (currently empty, falls back to global)
- Statistics tracking per worker
- Worker count set from RX thread count

### Phase 2 (Future)
- Populate per-worker tables during session creation
- Use lockless lookups when session is in worker's table
- Cross-worker access via global table (with locks)

## Testing

### Test Case 1: Worker Initialization
```bash
# Verify workers are initialized
yesrouterctl show nat statistics
# Should show worker count
```

### Test Case 2: Functional Test
```bash
# Clear sessions
yesrouterctl clear nat translations

# Run ping
ping -f 1.1.1.1 -c 100

# Check statistics
yesrouterctl show nat statistics
# Should show per-worker stats if multiple workers
```

### Test Case 3: Unit Test
```bash
cd /root/vbng
make test_nat_worker
./build/tests/test_nat_worker
```

## Expected Results

**Phase 1 (Current):**
- Infrastructure in place
- Falls back to global table (current behavior maintained)
- Statistics tracking works
- No functional changes

**Phase 2 (Future):**
- Lockless lookups for sessions in worker's table
- 10-50x throughput improvement
- Zero lock contention for same-worker lookups

## Next Steps

1. Complete Phase 2: Populate per-worker tables
2. Add packet queuing for ARP
3. Add performance metrics
4. Benchmark before/after
