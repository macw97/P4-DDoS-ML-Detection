import sys
import os
import json
import re
from scapy.all import sniff
from scapy.all import Packet
from scapy.all import IP,UDP,ICMP,Raw

from datetime import datetime

def handle_packet(packet,file):
    print("Controller received a packet")
    print(packet.summary())
    if ICMP in packet and packet[ICMP].type == 8:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_len = packet[IP].len
        print("time: {}, interface: {} , src:{} , dst:{} , length:{}".format(
            datetime.now(),packet.sniffed_on,ip_src,ip_dst,ip_len))
        file.write("{} {} {} {} {}\n".format(
            datetime.now(),packet.sniffed_on,ip_src,ip_dst,ip_len
        ))
        #os.system("echo {} {} {}".format(ip_src,ip_dst,ip_len))
    
def sniffer(list_of_interfaces,file):
    '''
    lack of iface assign in sniff function ends with TypeError
    '<' not supported between instances of 'int' and 'str'
    '''
    print("Sniffing on {} interfaces".format(list_of_interfaces))
    sys.stdout.flush()
    sniff(iface = list_of_interfaces, prn = lambda x: handle_packet(x,file))

def link_parser(links,target_switch):
    list_of_interfaces = []
    file = open("logs/packet_sniffer.log","w")
    for link in links:
        if len(link) == 2:
            if not re.match(r"h[0-9]+",link[0]):
                interface1 = "s{}-eth{}".format(link[0][1],link[0][4])
                interface2 = "s{}-eth{}".format(link[1][1],link[1][4])
                if interface1 not in list_of_interfaces:
                    print("Link_parser: {}".format(interface1[:2]))
                    if target_switch == interface1[:2]:
                        print("Link_praser: true add {}".format(interface1))
                        list_of_interfaces.append(interface1)
                    elif target_switch == "":
                        list_of_interfaces.append(interface1)

                if interface2 not in list_of_interfaces:
                    print("Link_parser: {}".format(interface2[:2]))
                    if target_switch == interface2[:2]:
                        print("Link_praser: true add {}".format(interface2))
                        list_of_interfaces.append(interface2)
                    elif target_switch == "":
                        list_of_interfaces.append(interface2)
    
    sniffer(list_of_interfaces,file)


def read_topology(switch_to_sniff,topo = "topology/topology.json"):
    if os.path.isfile(topo):
        pass
    else:
        print("Incorrect file path")
        exit(0)
    
    with open(topo,'r') as file:
        topology = json.load(file)
    
    link_parser(topology['links'],target_switch = switch_to_sniff)



if __name__ == '__main__':
    try:
        switch = sys.argv[1]
    except IndexError as e:
        print("No information which switch interfaces to sniff: {}".format(e))
        switch = ""
        pass

    read_topology(switch_to_sniff = switch)
