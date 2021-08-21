import sys
import os
import json
import re
from scapy.all import sniff
from scapy.all import Packet
from scapy.all import IP,UDP,ICMP,Raw

def handle_packet(packet):
    print("Controller received a packet")
    print(packet.summary())
    if ICMP in packet and packet[ICMP].type == 8:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_len = packet[IP].len
        print("src:{}, dst:{}, length:{}".format(ip_src,ip_dst,ip_len))
        os.system("echo {} {} {}".format(ip_src,ip_dst,ip_len))
    
def sniffer(list_of_interfaces):
    '''
    lack of iface assign in sniff function ends with TypeError
    '<' not supported between instances of 'int' and 'str'
    '''
    print("Sniffing on {} interfaces".format(list_of_interfaces))
    sys.stdout.flush()
    sniff(iface = list_of_interfaces, prn = lambda x: handle_packet(x))

def link_parser(links):
    list_of_interfaces = []
    for link in links:
        if len(link) == 2:
            if not re.match(r"h[0-9]+",link[0]):
                interface1 = "s{}-eth{}".format(link[0][1],link[0][4])
                interface2 = "s{}-eth{}".format(link[1][1],link[1][4])
                if interface1 not in list_of_interfaces:
                    list_of_interfaces.append(interface1)
                if interface2 not in list_of_interfaces:
                    list_of_interfaces.append(interface2)
    
    sniffer(list_of_interfaces)


def read_topology(topo = "topology/topology.json"):
    if os.path.isfile(topo):
        pass
    else:
        print("Incorrect file path")
        exit(0)
    
    with open(topo,'r') as file:
        topology = json.load(file)
    
    link_parser(topology['links'])



if __name__ == '__main__':
    
    read_topology()
