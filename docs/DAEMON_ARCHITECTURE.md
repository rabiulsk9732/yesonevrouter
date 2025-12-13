# YESRouter vs Accel-PPP Daemon Architecture

## Accel-PPP Architecture (What They Do Right)

### 1. Triton Framework (Event Loop)
```
┌─────────────────────────────────────────────────────────────┐
│                    TRITON CORE                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Thread 1   │  │  Thread 2   │  │  Thread N   │         │
│  │  (Worker)   │  │  (Worker)   │  │  (Worker)   │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│         └────────────────┼────────────────┘                 │
│                          │                                  │
│                    ┌─────▼─────┐                            │
│                    │  Context  │                            │
│                    │   Queue   │                            │
│                    └─────┬─────┘                            │
│                          │                                  │
│         ┌────────────────┼────────────────┐                 │
│         │                │                │                 │
│    ┌────▼────┐     ┌─────▼─────┐    ┌─────▼─────┐          │
│    │ Timers  │     │  MD (FD)  │    │  Calls    │          │
│    │ Handler │     │  Handler  │    │  Handler  │          │
│    └─────────┘     └───────────┘    └───────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### Key Components:
1. **triton_context_t** - Each session/connection has its own context
2. **triton_md_handler_t** - File descriptor (socket) event handlers
3. **triton_timer_t** - Timer management
4. **triton_context_call** - Cross-context function calls
5. **Worker threads** - Process contexts from queue

### 2. Module System
```c
// Each module registers itself
static void __init pppoe_init(void)
{
    triton_context_register(&serv.ctx, NULL);
    triton_md_register_handler(&serv.ctx, &serv.hnd);
    triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
    triton_context_wakeup(&serv.ctx);
}
```

### 3. Configuration System
- INI-style config file (`accel-ppp.conf`)
- Sections: `[modules]`, `[core]`, `[pppoe]`, `[radius]`, etc.
- Runtime reload support

### 4. Service Lifecycle
```
1. Load config
2. Initialize triton (thread pool)
3. Load modules (pppoe, radius, etc.)
4. Each module registers contexts
5. Main loop: triton_run()
6. Signal handlers for reload/shutdown
```

---

## What YESRouter is Missing

### 1. ❌ No Proper Event Loop
**Current:** DPDK poll loop only
**Need:** Separate event loop for:
- CLI socket handling
- RADIUS responses
- Timer management
- Signal handling

### 2. ❌ No Context System
**Current:** Global state, no per-session context
**Need:** Each PPPoE/IPoE session should have its own context with:
- Timers (LCP echo, session timeout)
- State machine
- Callbacks

### 3. ❌ No Module System
**Current:** Everything compiled together
**Need:** Dynamic module loading or at least clean module init/cleanup

### 4. ❌ No Proper Signal Handling
**Current:** Basic signal handling
**Need:**
- SIGHUP for config reload
- SIGTERM/SIGINT for graceful shutdown
- SIGUSR1/2 for debug/stats

### 5. ❌ No Config Reload
**Current:** Config loaded once at startup
**Need:** Runtime config reload without restart

---

## Proposed YESRouter Daemon Architecture

### 1. Core Event System (DPDK + epoll hybrid)
```
┌─────────────────────────────────────────────────────────────┐
│                    YESROUTER CORE                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────┐    ┌─────────────────────┐        │
│  │   DPDK Poll Loop    │    │   Control Plane     │        │
│  │   (Fast Path)       │    │   (epoll loop)      │        │
│  │                     │    │                     │        │
│  │  - Packet RX/TX     │    │  - CLI socket       │        │
│  │  - PPPoE/IPoE       │    │  - RADIUS client    │        │
│  │  - NAT              │    │  - Timers           │        │
│  │  - QoS              │    │  - Signals          │        │
│  └─────────────────────┘    └─────────────────────┘        │
│           │                          │                      │
│           └──────────┬───────────────┘                      │
│                      │                                      │
│              ┌───────▼───────┐                              │
│              │  Shared State │                              │
│              │  (lockless)   │                              │
│              └───────────────┘                              │
└─────────────────────────────────────────────────────────────┘
```

### 2. Configuration Files
```
/etc/yesrouter/
├── yesrouter.conf      # System config (VPP-style)
│   ├── cpu { }
│   ├── dpdk { }
│   ├── unix { }
│   └── logging { }
│
└── startup.json        # Router config (JSON)
    ├── interfaces
    ├── pppoe
    ├── radius
    └── ip-pool
```

### 3. Systemd Service
```ini
[Unit]
Description=YESRouter vBNG
After=network.target

[Service]
Type=notify
ExecStart=/usr/bin/yesrouter -c /etc/yesrouter/yesrouter.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
LimitMEMLOCK=infinity
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### 4. Signal Handling
```c
SIGHUP  -> config_reload()
SIGTERM -> graceful_shutdown()
SIGINT  -> graceful_shutdown()
SIGUSR1 -> dump_stats()
SIGUSR2 -> toggle_debug()
```

---

## Implementation Priority

### Phase 1: Control Plane Thread
1. Create separate control plane thread
2. epoll-based event loop for:
   - CLI socket
   - RADIUS UDP socket
   - Timer fd

### Phase 2: Timer System
1. timerfd-based timer management
2. Per-session timers
3. Global timers (stats, cleanup)

### Phase 3: Signal Handling
1. signalfd for clean signal handling
2. Config reload support
3. Graceful shutdown

### Phase 4: Module System
1. Module init/cleanup interface
2. Dependency ordering
3. Runtime enable/disable
