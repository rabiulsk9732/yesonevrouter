#!/bin/bash
# Clean startup script with logs redirected to file

cd /root/vbng

# Kill any existing instances
pkill -9 yesrouter 2>/dev/null
rm -rf /var/run/dpdk/rte/config 2>/dev/null
sleep 1

# Create log directory
mkdir -p logs

# Create named pipe for commands
FIFO=/tmp/vbng_cmd
rm -f $FIFO
mkfifo $FIFO

echo "=========================================="
echo "Starting YESRouter vBNG (Background Mode)"
echo "=========================================="
echo ""
echo "Logs will be written to: logs/yesrouter.log"
echo ""

# Start vBNG with logs redirected
exec 3<>$FIFO
cat $FIFO | ./build/yesrouter > logs/yesrouter.log 2>&1 &
VBNG_PID=$!

sleep 3

# Send authentication
echo "admin" > $FIFO
sleep 1
echo "admin" > $FIFO
sleep 2

# Enter privileged mode
echo "enable" > $FIFO
sleep 1

# Configure interface Gi0/1
echo "configure terminal" > $FIFO
sleep 1
echo "interface Gi0/1" > $FIFO
sleep 1
echo "ip address 103.174.247.67 255.255.255.192" > $FIFO
sleep 1
echo "no shutdown" > $FIFO
sleep 1
echo "exit" > $FIFO
sleep 1

# Add default route
echo "ip route 0.0.0.0 0.0.0.0 103.174.247.65" > $FIFO
sleep 1
echo "end" > $FIFO
sleep 2

echo "✅ YESRouter started successfully!"
echo ""
echo "Router PID: $VBNG_PID"
echo "IP Address: 103.174.247.67/26"
echo "Gateway: 103.174.247.65"
echo ""
echo "📋 Send commands:"
echo "  echo 'show interfaces' > /tmp/vbng_cmd"
echo "  echo 'show ip route' > /tmp/vbng_cmd"
echo "  echo 'ping 8.8.8.8 5' > /tmp/vbng_cmd"
echo "  echo 'traceroute 8.8.8.8' > /tmp/vbng_cmd"
echo ""
echo "📄 View logs:"
echo "  tail -f logs/yesrouter.log"
echo ""
echo "🛑 Stop router:"
echo "  pkill yesrouter"
echo ""
