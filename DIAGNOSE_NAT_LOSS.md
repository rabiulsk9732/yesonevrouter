# Diagnose NAT Packet Loss: Host vs Client

## Observation

**Host (router itself):**
- `ping -f 1.1.1.1`: 9970 packets, 9969 received, **0.01% loss** ✅

**Client (through NAT):**
- Normal ping: **0% loss** ✅
- Flood ping: **30%, 2.2%, 17.5% loss** ❌

## Diagnosis Steps

### 1. Check NAT Statistics

```bash
# On router
yesrouterctl show nat statistics
```

Look for:
- `ICMP echo requests` vs `ICMP echo replies`
- `ICMP identifier mismatches`
- `Out2In misses` (DNAT lookup failures)
- `In2Out misses` (SNAT lookup failures)

### 2. Check Active Sessions

```bash
yesrouterctl show nat translations | grep ICMP
```

### 3. Monitor in Real-Time

```bash
# Terminal 1: Monitor statistics
watch -n 1 'yesrouterctl show nat statistics | grep -A 10 "ICMP\|Lookup"'

# Terminal 2: Run flood ping from client
ping -f 1.1.1.1
```

### 4. Check for Session Timeout Issues

```bash
# Check session timeout settings
yesrouterctl show nat config
```

ICMP timeout is 60 seconds - if flood ping runs longer, sessions may expire.

### 5. Compare Host vs Client Path

**Host path (no NAT):**
- Router → Direct forwarding → No NAT translation
- No session lookup overhead
- No lock contention

**Client path (with NAT):**
- Client → SNAT (in2out lookup) → Forward → DNAT (out2in lookup)
- Two session lookups per packet
- Lock contention under flood
- Possible hash collisions

## Expected Issues

1. **Lock Contention**: Multiple RX threads contending for same hash bucket locks
2. **Session Timeout**: Sessions expiring during flood ping
3. **Hash Collisions**: Different ICMP identifiers hashing to same bucket
4. **Memory Pressure**: Session allocation failures under load

## Next Steps

Run the diagnostics above and share the output.
