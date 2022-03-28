from scapy.all import *

TYPE_EXTRA = 0xA1
TYPE_IPV4 = 0x0800

class Extra(Packet):
    name = "extra"
    fields_desc = [
        IntField("total_pck",0),
        IntField("tcp_pck",0),
        IntField("tcp_syn_pck",0),
        IntField("udp_pck",0),
        IntField("icmp_pck",0),
        IntField("total_len",0)
    ]
    
    def mysummary(self):
        return self.sprintf("total_pck = %total_pck%, tcp_pck = %tcp_pck%, tcp_syn = %tcp_syn_pck%, udp_pck = %udp_pck%, icmp_pck = %icmp_cpk%, total_len = %total_len%")

    def extract_padding(self, s):
        return "",s

bind_layers(IP, Extra, proto = TYPE_EXTRA)
bind_layers(Extra, Padding)