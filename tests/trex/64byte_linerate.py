#!/usr/bin/env python3
"""
TRex Profile: 64-byte Line Rate Test
Target: 14.88 Mpps @ 10Gbps (theoretical max for 64-byte frames)

RFC 2544 compliant - tests maximum packet rate with minimum frame size
"""

from trex_stl_lib.api import *

class STLLinerate64(object):
    """64-byte line rate test profile"""

    def __init__(self):
        # 64-byte frame = 14 (Eth) + 20 (IP) + 8 (UDP) + 22 (payload) = 64
        # Wire size = 64 + 4 (FCS) + 12 (IFG) + 8 (Preamble) = 84 bytes
        # Max PPS @ 10Gbps = 10e9 / (84 * 8) = 14,880,952 pps
        self.max_pps = 14880952

    def create_stream(self, dst_mac, src_mac, src_ip, dst_ip):
        """Create 64-byte UDP stream"""

        # Build packet - exactly 64 bytes
        pkt = Ether(dst=dst_mac, src=src_mac) / \
              IP(src=src_ip, dst=dst_ip, ttl=64) / \
              UDP(sport=1024, dport=80) / \
              Raw(load='X' * 22)  # Padding to reach 64 bytes

        # Verify size
        assert len(pkt) == 64, f"Packet size is {len(pkt)}, expected 64"

        # Create continuous stream at line rate
        return STLStream(
            name='linerate_64',
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(pps=self.max_pps)
        )

    def get_streams(self, tunables, **kwargs):
        """Return list of streams"""

        # Default MACs - update for your environment
        dst_mac = tunables.get('dst_mac', '90:e2:ba:99:92:5c')
        src_mac = tunables.get('src_mac', '90:e2:ba:99:92:5d')
        src_ip = tunables.get('src_ip', '10.0.0.1')
        dst_ip = tunables.get('dst_ip', '192.168.1.1')

        return [self.create_stream(dst_mac, src_mac, src_ip, dst_ip)]


def register():
    return STLLinerate64()


# Standalone test
if __name__ == '__main__':
    print("64-byte Line Rate Test Profile")
    print(f"Target: 14.88 Mpps @ 10Gbps")

    profile = STLLinerate64()
    streams = profile.get_streams({})

    for s in streams:
        print(f"Stream: {s.get_name()}")
