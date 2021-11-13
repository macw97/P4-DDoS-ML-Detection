import sys
import os
import json
import re
from scapy.all import sniff
from scapy.all import Packet
from scapy.all import IP,UDP,ICMP,TCP,Raw
from extra_header import Extra

from datetime import datetime

def packet_summary(packet,file,type):
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    ip_len = packet[IP].len
    packet.show2()
    if packet.sniffed_on == 's1-eth3':
        if Extra in packet:
            print("============== I GOT YOU ==============")
        print("time: {}, interface: {}, length: {}".format(datetime.now(),packet.sniffed_on,packet[IP].len))
    else:
        print("time: {}, type: {}, interface: {}, src:{}, dst:{}, length:{}".format(
            datetime.now(),type,packet.sniffed_on,ip_src,ip_dst,ip_len))
        file.write("{} {} {} {} {}\n".format(
            datetime.now(),type,packet.sniffed_on,ip_src,ip_dst,ip_len
        ))

def handle_packet(packet,file):
    print("Controller received a packet")
    print(packet.summary())
    #if ICMP in packet and packet[ICMP].type == 8:
    if ICMP in packet:
        packet_summary(packet,file,"ICMP")
    elif TCP in packet: 
        packet_summary(packet,file,"TCP")
    elif UDP in packet:
        packet_summary(packet,file,"UDP")
    else:
        packet_summary(packet,file,"EXTRA")
    
    file.flush()

    
def sniffer(list_of_interfaces,file):
    '''
    lack of iface assign in sniff function ends with TypeError
    '<' not supported between instances of 'int' and 'str'
    '''
    print("Sniffing on {} interfaces".format(list_of_interfaces))
    sys.stdout.flush()
    sniff(iface = list_of_interfaces, prn = lambda x: handle_packet(x,file))

def check(list_of_interfaces,switch,interface):
    
    if interface not in list_of_interfaces:
                print("Link_parser: {}".format(interface[:2]))
                if switch == interface[:2]:
                    print("Link_praser: true add {}".format(interface))
                    list_of_interfaces.append(interface)
                elif switch == "":
                    list_of_interfaces.append(interface)


def link_parser(links,target_switch):
    list_of_interfaces = []
    file = open("log/packet_sniffer.log","w")
    for link in links:
        
        if not re.match(r"h[0-9]+",link['source']) and not re.match(r"h[0-9]+",link['target']):
            interface1 = link['intfName1']
            interface2 = link['intfName2']

            check(list_of_interfaces,target_switch,interface1)
            check(list_of_interfaces,target_switch,interface2)
    
    list_of_interfaces.append('s1-eth3')
    sniffer(list_of_interfaces,file)


def read_topology(switch_to_sniff,topo = "topology.json"):
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
