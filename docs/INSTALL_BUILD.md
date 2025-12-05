# Install Build Instructions

## Build Successful! ✅

The executable is at: `/root/vbng/build/yesrouter`

## Install Steps

From `/root/vbng#` (current directory):

```bash
# Stop the service
sudo systemctl stop yesrouter

# Copy the new binary
sudo cp build/yesrouter /usr/local/bin/

# Start the service
sudo systemctl start yesrouter

# Verify it's running
sudo systemctl status yesrouter
```

## Test the NAT Fixes

After installing, test the new ICMP statistics:

```bash
# Clear existing sessions
yesrouterctl clear nat translations

# Run a test ping
ping -f 8.8.8.8 -c 100

# Check the new statistics
yesrouterctl show nat statistics
```

You should now see:
- **ICMP Statistics** section with:
  - ICMP echo requests
  - ICMP echo replies
  - ICMP identifier mismatches
  - ICMP session race failures

## What Changed

This build includes:
1. ✅ ICMP-specific statistics tracking
2. ✅ Enhanced ICMP echo request/reply detection
3. ✅ Session validation in DNAT lookup
4. ✅ Improved error logging

These statistics will help diagnose the intermittent NAT failures.
