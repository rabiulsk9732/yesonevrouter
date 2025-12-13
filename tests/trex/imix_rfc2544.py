#!/usr/bin/env python3
"""
TRex Profile: IMIX RFC 2544 Test
Mixed traffic pattern: 64/512/1500 bytes (7:4:1 ratio)

Standard IMIX distribution for realistic network traffic simulation
"""

from trex_stl_lib.api import *

class STLIMIX2544(object):
    """IMIX RFC 2544 test profile"""

    def __init__(self):
        # IMIX distribution (by packet count): 7:4:1
        # 64 bytes: 58.33%
        # 512 bytes: 33.33%
        # 1500 bytes: 8.33%
        #
        # Average packet size: (7*64 + 4*512 + 1*1500) / 12 = 340 bytes
        # Max PPS @ 10Gbps with 340 avg = ~3.5 Mpps
        pass

    def create_streams(self, dst_mac, src_mac, base_src_ip, base_dst_ip):
        """Create IMIX stream set"""

        streams = []

        # Stream 1: 64-byte packets (high rate)
        pkt_64 = Ether(dst=dst_mac, src=src_mac) / \
                 IP(src=base_src_ip, dst=base_dst_ip, ttl=64) / \
                 UDP(sport=1024, dport=80) / \
                 Raw(load='X' * 22)

        streams.append(STLStream(
            name='imix_64',
            packet=STLPktBuilder(pkt=pkt_64),
            mode=STLTXCont(pps=7000000)  # 7M pps
        ))

        # Stream 2: 512-byte packets (medium rate)
        pkt_512 = Ether(dst=dst_mac, src=src_mac) / \
                  IP(src=base_src_ip, dst=base_dst_ip, ttl=64) / \
                  UDP(sport=1025, dport=80) / \
                  Raw(load='Y' * 470)

        streams.append(STLStream(
            name='imix_512',
            packet=STLPktBuilder(pkt=pkt_512),
            mode=STLTXCont(pps=4000000)  # 4M pps
        ))

        # Stream 3: 1500-byte packets (low rate)
        pkt_1500 = Ether(dst=dst_mac, src=src_mac) / \
                   IP(src=base_src_ip, dst=base_dst_ip, ttl=64) / \
                   UDP(sport=1026, dport=80) / \
                   Raw(load='Z' * 1458)

        streams.append(STLStream(
            name='imix_1500',
            packet=STLPktBuilder(pkt=pkt_1500),
            mode=STLTXCont(pps=1000000)  # 1M pps
        ))

        return streams

    def get_streams(self, tunables, **kwargs):
        """Return list of streams"""

        dst_mac = tunables.get('dst_mac', '90:e2:ba:99:92:5c')
        src_mac = tunables.get('src_mac', '90:e2:ba:99:92:5d')
        src_ip = tunables.get('src_ip', '10.0.0.1')
        dst_ip = tunables.get('dst_ip', '192.168.1.1')

        return self.create_streams(dst_mac, src_mac, src_ip, dst_ip)


def register():
    return STLIMIX2544()


if __name__ == '__main__':
    print("IMIX RFC 2544 Test Profile")
    print("Distribution: 64B (7), 512B (4), 1500B (1)")
    print("Average packet size: ~340 bytes")
