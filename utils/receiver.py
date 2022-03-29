import sys, os, json, re
import scapy.all as scapy
from extra_header import Extra
import ipaddress
import numpy as np
from datetime import datetime
from scipy.stats import entropy

entropy_src_ip_val = 0
entropy_dport_val = 0
src_vec = []
dst_port_vec = []

log_format = "{DATE} {PCK} {TCP} {TCP_SYN} {UDP} {ICMP} {AVG} {IP_ENTROPY} {PORT_ENTROPY}\n"

def entropy_calc(data, base = None):
    values, counts = np.unique(data, return_counts= True)
    return entropy(counts, base = base)    

def packet_summary(packet, file):
    
    if Extra in packet:
        entropy_src_ip_val = entropy_calc(src_vec)
        entropy_dport_val = entropy_calc(dst_port_vec)
        total_pck = packet[Extra].total_pck
        tcp_pck = packet[Extra].tcp_pck
        tcp_syn_pck = packet[Extra].tcp_syn_pck
        udp_pck = packet[Extra].udp_pck
        icmp_pck = packet[Extra].icmp_pck
        total_len = packet[Extra].total_len
        avg_len = total_len/total_pck
        file.write(log_format.format(DATE = datetime.now(),
                                     PCK = total_pck,
                                     TCP = tcp_pck,
                                     TCP_SYN = tcp_syn_pck,
                                     UDP = udp_pck,
                                     ICMP = icmp_pck,
                                     AVG = avg_len,
                                     IP_ENTROPY = entropy_src_ip_val,
                                     PORT_ENTROPY = entropy_dport_val))
        src_vec.clear()
        dst_port_vec.clear()
        entropy_src_ip_val = 0
        entropy_dport_val = 0
    else:
        ip_src = packet[scapy.IP].src
        if scapy.TCP in packet:
            ip_port = packet[scapy.TCP].dport
            dst_port_vec.append(int(ip_port))
        elif scapy.UDP in packet:
            ip_port = packet[scapy.UDP].dport
            dst_port_vec.append(int(ip_port))
    
        src_vec.append(ipaddress.ip_address(ip_src))
    
    packet.show2()

def handle_packet(packet, file):
    print("\n\n\nController received a packet")
    print(packet.summary())
    packet_summary(packet, file)
    
    file.flush()

    
def sniffer(list_of_interfaces, file):
    print("Sniffing on {} interfaces".format(list_of_interfaces))
    sys.stdout.flush()
    scapy.sniff(iface = list_of_interfaces, prn = lambda x: handle_packet(x,file), store = 0)

def check(list_of_interfaces, switch, interface):
    
    if interface not in list_of_interfaces and switch == interface[:2]:
        print("Link_praser: true add {}".format(interface))
        list_of_interfaces.append(interface)


def link_parser(links, target_switch):
    
    list_of_interfaces = []
    for link in links:
        
        if not re.match(r"h[0-9]+",link['source']) and not re.match(r"h[0-9]+",link['target']):
            interface1 = link['intfName1']
            interface2 = link['intfName2']

            check(list_of_interfaces, target_switch, interface1)
            check(list_of_interfaces, target_switch, interface2)
    
    list_of_interfaces.append('s1-eth3')
    file = open("log/entropy_packets_sniffer.log","w")

    sniffer(list_of_interfaces,file)


def read_topology(switch_to_sniff, topo = "topology.json"):
    if os.path.isfile(topo):
        pass
    else:
        print("Incorrect file path")
        exit(0)
    
    with open(topo,'r') as file:
        topology = json.load(file)
    
    link_parser(topology['links'], switch_to_sniff)



if __name__ == '__main__':
    try:
        switch = sys.argv[1]
    except IndexError as e:
        print("No information which switch interfaces to sniff: {}".format(e))
        switch = "s1"
        pass

    read_topology(switch)
