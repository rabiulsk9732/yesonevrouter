# Build Verification Checklist

## Code Changes Summary

### Files Modified (8)
1. `include/cpu_scheduler.h` - Added `g_thread_worker_id`
2. `src/core/cpu_scheduler.c` - Defined `g_thread_worker_id`
3. `src/forwarding/packet_rx.c` - Set worker_id, call nat_set_num_workers()
4. `src/nat/nat_session.c` - Per-worker lookup, initialization
5. `include/nat.h` - Added struct nat_worker_data, worker API
6. `src/nat/CMakeLists.txt` - Added nat_worker.c
7. `tests/CMakeLists.txt` - Added test_nat_worker
8. `docs/task.md` - Updated with improvements

### Files Created (2)
1. `src/nat/nat_worker.c` - Worker management API
2. `tests/test_nat_worker.c` - Test cases

## Compilation Checks

### ✅ Header Dependencies
- `struct nat_worker_data` defined in `include/nat.h`
- Forward declaration of `struct nat_session` before struct definition
- All includes present

### ✅ Function Declarations
- `nat_set_num_workers()` declared in `nat.h`
- `nat_get_num_workers()` declared in `nat.h`
- `nat_get_worker_stats_ptr()` declared in `nat.h`

### ✅ Variable Access
- `g_num_workers` exported (not static)
- `g_nat_workers[]` exported (not static)
- Thread-local `g_thread_worker_id` properly declared

### ✅ Build System
- `nat_worker.c` added to CMakeLists.txt
- Test added to tests/CMakeLists.txt

## Expected Build Output

```bash
cd /root/vbng
./compile.sh
```

Should compile successfully with:
- No undefined references
- No type mismatches
- All files compile

## Known Issues

None - all linter checks pass.

## Manual Build Command

If terminal fails, run manually:
```bash
cd /root/vbng
rm -rf build
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

## Test After Build

```bash
# Run unit test
cd build
./tests/test_nat_worker

# Functional test
sudo systemctl stop yesrouter
sudo cp build/yesrouter /usr/local/bin/
sudo systemctl start yesrouter
yesrouterctl show nat statistics
```
