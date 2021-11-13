from scapy.all import *
import sys, os

TYPE_EXTRA = 0xA1
TYPE_IPV4 = 0x0800

class Extra(Packet):
    name = "extra"
    fields_desc = [
        IntField("total_pck",0),
        ShortField("tcp_pck",0),
        ShortField("udp_pck",0),
        ShortField("icmp_pck",0)
    ]
    
    def mysummary(self):
        return self.sprintf("total_pck = %total_pck%, tcp_pck = %tcp_pck%, udp_pck = %udp_pck%, icmp_pck = %icmp_cpk%")

bind_layers(IP, Extra, proto= TYPE_EXTRA)