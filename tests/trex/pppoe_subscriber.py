#!/usr/bin/env python3
"""
TRex Profile: PPPoE Subscriber Emulation
Emulates PPPoE subscriber traffic with proper encapsulation

Note: This generates data-plane traffic for established PPPoE sessions
PPPoE discovery (PADI/PADO/PADR/PADS) requires stateful testing
"""

from trex_stl_lib.api import *
import struct

class STLPPPoESubscriber(object):
    """PPPoE subscriber traffic emulation"""

    def create_pppoe_packet(self, dst_mac, src_mac, session_id, src_ip, dst_ip, payload_size=22):
        """Create PPPoE encapsulated IPv4 packet"""

        # PPPoE Session header
        # Ver(4b)=1, Type(4b)=1, Code=0x00 (Session), Session ID, Length
        pppoe_ver_type = 0x11  # Version 1, Type 1
        pppoe_code = 0x00      # Session data
        ppp_protocol = 0x0021  # IPv4

        # Build PPPoE header manually
        pppoe_hdr = struct.pack('!BBH', pppoe_ver_type, pppoe_code, session_id)

        # Inner IP packet
        inner_pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
                    UDP(sport=1024, dport=80) / \
                    Raw(load='P' * payload_size)

        # PPPoE length = PPP protocol (2) + IP packet length
        pppoe_len = 2 + len(inner_pkt)
        pppoe_hdr += struct.pack('!H', pppoe_len)
        pppoe_hdr += struct.pack('!H', ppp_protocol)

        # Complete packet
        pkt = Ether(dst=dst_mac, src=src_mac, type=0x8864) / \
              Raw(load=pppoe_hdr) / \
              inner_pkt

        return pkt

    def create_streams(self, dst_mac, src_mac, session_id, src_ip, dst_ip):
        """Create PPPoE subscriber traffic streams"""

        streams = []

        # Standard PPPoE session traffic
        pkt = self.create_pppoe_packet(dst_mac, src_mac, session_id, src_ip, dst_ip)

        streams.append(STLStream(
            name='pppoe_subscriber',
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(pps=1000000)  # 1M pps per subscriber
        ))

        return streams

    def get_streams(self, tunables, **kwargs):
        # vBNG MAC (AC side)
        dst_mac = tunables.get('dst_mac', '90:e2:ba:99:92:5c')
        # Subscriber MAC
        src_mac = tunables.get('src_mac', '00:11:22:33:44:55')
        # PPPoE Session ID (assigned by AC)
        session_id = tunables.get('session_id', 1)
        # Subscriber IP (assigned via IPCP)
        src_ip = tunables.get('src_ip', '100.64.0.10')
        # Destination IP
        dst_ip = tunables.get('dst_ip', '8.8.8.8')

        return self.create_streams(dst_mac, src_mac, session_id, src_ip, dst_ip)


def register():
    return STLPPPoESubscriber()


if __name__ == '__main__':
    print("PPPoE Subscriber Emulation Profile")
    print("Generates PPPoE-encapsulated IPv4 traffic")
    print("Use for data-plane testing of established sessions")
