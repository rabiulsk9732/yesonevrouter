#!/usr/bin/env python3
"""
TRex Profile: NAT44 Scale Test
Tests NAT session creation rate and capacity

Generates flows with varying source ports to create unique NAT sessions
"""

from trex_stl_lib.api import *

class STLNATScale(object):
    """NAT44 scale test profile"""

    def create_stream(self, dst_mac, src_mac, src_ip_start, dst_ip, num_flows):
        """Create stream with variable source IPs/ports for NAT testing"""

        # Base packet
        pkt = Ether(dst=dst_mac, src=src_mac) / \
              IP(src=src_ip_start, dst=dst_ip, ttl=64) / \
              UDP(sport=1024, dport=80) / \
              Raw(load='N' * 22)

        # Field Engine for varying source IP and port
        vm = STLScVmRaw([
            # Vary source IP: 10.0.0.1 - 10.0.255.255 (65535 IPs)
            STLVmFlowVar(name="src_ip",
                        min_value="10.0.0.1",
                        max_value="10.0.255.255",
                        size=4, op="inc"),
            STLVmWrFlowVar(fv_name="src_ip", pkt_offset="IP.src"),

            # Vary source port: 1024-65535
            STLVmFlowVar(name="src_port",
                        min_value=1024,
                        max_value=65535,
                        size=2, op="inc"),
            STLVmWrFlowVar(fv_name="src_port", pkt_offset="UDP.sport"),

            # Fix checksums
            STLVmFixIpv4(offset="IP"),
            STLVmFixChecksumHw(l3_offset="IP", l4_offset="UDP", l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)
        ])

        return STLStream(
            name='nat_scale',
            packet=STLPktBuilder(pkt=pkt, vm=vm),
            mode=STLTXCont(pps=1000000)  # 1M new flows/sec
        )

    def get_streams(self, tunables, **kwargs):
        dst_mac = tunables.get('dst_mac', '90:e2:ba:99:92:5c')
        src_mac = tunables.get('src_mac', '90:e2:ba:99:92:5d')
        src_ip = tunables.get('src_ip', '10.0.0.1')
        dst_ip = tunables.get('dst_ip', '192.168.1.1')
        num_flows = tunables.get('num_flows', 1000000)

        return [self.create_stream(dst_mac, src_mac, src_ip, dst_ip, num_flows)]


def register():
    return STLNATScale()


if __name__ == '__main__':
    print("NAT44 Scale Test Profile")
    print("Tests session creation rate and capacity")
    print("Generates unique flows with varying src IP/port")
