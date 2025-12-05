# CMake Configuration Guide

## Quick Build (Recommended)

The project uses CMake. The easiest way to build is:

```bash
cd /root/vbng
./compile.sh
```

This script automatically:
1. Creates a `build/` directory
2. Runs `cmake ..` to configure
3. Runs `make -j$(nproc)` to build
4. Verifies the build

## Manual Configuration

If you want to configure manually:

```bash
cd /root/vbng
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

## CMake Configuration Options

Available options (set with `-D`):

```bash
cmake -DENABLE_DPDK=ON ..
cmake -DENABLE_TESTS=ON ..
cmake -DENABLE_BENCHMARKS=ON ..
cmake -DENABLE_ASAN=ON ..  # AddressSanitizer for debugging
cmake -DCMAKE_BUILD_TYPE=Debug ..  # Debug build
cmake -DCMAKE_BUILD_TYPE=Release ..  # Release build (default)
```

### Example: Debug Build with Tests

```bash
cd /root/vbng
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTS=ON ..
make -j$(nproc)
```

### Example: Release Build with DPDK

```bash
cd /root/vbng
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_DPDK=ON ..
make -j$(nproc)
```

## Viewing Current Configuration

After running `cmake`, you can see the configuration:

```bash
cd build
cmake -L ..  # List all variables
cmake -LA .. # List all variables with advanced ones
```

## Reconfiguring

To change options and reconfigure:

```bash
cd build
cmake ..  # Reconfigure with new options
make -j$(nproc)
```

Or clean and start fresh:

```bash
cd /root/vbng
rm -rf build
./compile.sh
```

## Common Issues

### "CMake not found"
```bash
sudo apt-get install cmake
```

### "DPDK not found"
Make sure DPDK is installed and `PKG_CONFIG_PATH` is set:
```bash
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
```

### "Permission denied"
Make sure you have write access to the build directory:
```bash
chmod -R u+w build/
```
