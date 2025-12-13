#!/usr/bin/env python3
"""
TRex Profile: Latency Measurement Test
Measures forwarding latency with timestamped packets

Uses TRex latency streams for accurate RTT measurement
"""

from trex_stl_lib.api import *

class STLLatencyTest(object):
    """Latency measurement test profile"""

    def create_streams(self, dst_mac, src_mac, src_ip, dst_ip):
        """Create latency measurement streams"""

        streams = []

        # Background traffic stream (64-byte, moderate rate)
        pkt_bg = Ether(dst=dst_mac, src=src_mac) / \
                 IP(src=src_ip, dst=dst_ip, ttl=64) / \
                 UDP(sport=1024, dport=80) / \
                 Raw(load='B' * 22)

        streams.append(STLStream(
            name='background',
            packet=STLPktBuilder(pkt=pkt_bg),
            mode=STLTXCont(pps=5000000)  # 5M pps background
        ))

        # Latency measurement stream (with flow stats)
        pkt_lat = Ether(dst=dst_mac, src=src_mac) / \
                  IP(src=src_ip, dst=dst_ip, ttl=64) / \
                  UDP(sport=12345, dport=12345) / \
                  Raw(load='L' * 22)

        streams.append(STLStream(
            name='latency',
            packet=STLPktBuilder(pkt=pkt_lat),
            mode=STLTXCont(pps=1000),  # 1K pps for latency
            flow_stats=STLFlowLatencyStats(pg_id=0)
        ))

        return streams

    def get_streams(self, tunables, **kwargs):
        dst_mac = tunables.get('dst_mac', '90:e2:ba:99:92:5c')
        src_mac = tunables.get('src_mac', '90:e2:ba:99:92:5d')
        src_ip = tunables.get('src_ip', '10.0.0.1')
        dst_ip = tunables.get('dst_ip', '192.168.1.1')

        return self.create_streams(dst_mac, src_mac, src_ip, dst_ip)


def register():
    return STLLatencyTest()


if __name__ == '__main__':
    print("Latency Measurement Test Profile")
    print("Background: 5M pps, Latency probe: 1K pps")
