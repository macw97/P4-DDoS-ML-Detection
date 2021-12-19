import sys
import os
import random
from scapy.all import *
import signal
import concurrent.futures
import urllib.request
import time

networks = {
    "10.0.1.0" : ["10.0.1.1","10.0.1.2","10.0.1.4","10.0.1.5"],
    "10.0.2.0" : ["10.0.2.6","10.0.2.7","10.0.2.8","10.0.2.9","10.0.2.10"],
    "10.0.3.0" : ["10.0.3.11","10.0.3.12","10.0.3.13","10.0.3.14","10.0.3.15"]
}

message = [
    "TCP",
    "UDP",
    "ICMP"
]

random_packet_vec = []

def packet(message_type,host,payload_size):

    m = None
    if message_type == "TCP":
        m = Ether()/IP(dst=host)/fuzz(TCP())/Raw(RandString(size=payload_size))
    elif message_type == "UDP":
        m = Ether()/IP(dst=host)/fuzz(UDP())/Raw(RandString(size=payload_size))
    elif message_type == "ICMP":
        m = Ether()/IP(dst=host)/fuzz(ICMP())/Raw(RandString(size=payload_size))
    
    return m

def network_to_send_traffic(net):
    
    for i in range(150):
        host = random.choice(networks[net])
        mess_type = random.choice(message)
        payload_size = random.randint(30,400)
        to_send = packet(mess_type,host,payload_size)
        print("Packet {} creation {} to {}".format(i,mess_type,host))
        if to_send is not None:
            random_packet_vec.append(to_send)
        
    while True:    
        amount = random.randint(5,100)
        p = random.choice(random_packet_vec)
        if UDP in p:
            print("Messages: UDP , Amount: {}".format(amount))
        elif TCP in p:
            print("Messages: TCP , Amount: {}".format(amount))
        elif ICMP in p: 
            print("Messages: ICMP , Amount: {}".format(amount))

        sendpfast(p, pps = 5000, loop = amount)

def ctrl_c_handler(s,f):
    print("\t\tCtrl+C")
    exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, ctrl_c_handler)
    try:
        net = sys.argv[1]
    except IndexError as e:
        print("No network ip to send traffic: {}".format(e))
    
    if net in networks:
        network_to_send_traffic(net)
    else:
        print("There is no such network : {}".format(net))

