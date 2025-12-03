FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    meson \
    ninja-build \
    pkg-config \
    git \
    wget \
    curl \
    vim \
    gdb \
    valgrind \
    clang \
    clang-format \
    cppcheck \
    python3 \
    python3-pip \
    python3-pyelftools \
    libnuma-dev \
    libpcap-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install DPDK dependencies
RUN apt-get update && apt-get install -y \
    libnuma-dev \
    libarchive-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace/yesrouter

# Copy project files
COPY . /workspace/yesrouter/

# Build instructions (commented out, run manually)
# RUN mkdir -p build && cd build && cmake .. && make -j$(nproc)

CMD ["/bin/bash"]
