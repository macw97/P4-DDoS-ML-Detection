import sys
import os
import random
import scapy.all as scapy 
import signal

networks = {
    "10.0.1.0" : ["10.0.1.1","10.0.1.2"],
    "10.0.2.0" : ["10.0.2.4","10.0.2.5","10.0.2.6"],
    "10.0.3.0" : ["10.0.3.7","10.0.3.8","10.0.3.9"]
}

message = [
    "TCP",
    "UDP",
    "ICMP"
]

def packet(message_type,host):

    m = None
    if message_type == "TCP":
        m = scapy.IP(dst=host)/scapy.TCP(dport=random.randrange(1200,2600,2))
    elif message_type == "UDP":
        m = scapy.IP(dst=host)/scapy.UDP(dport=random.randrange(1200,2600,2))
    elif message_type == "ICMP":
        m = scapy.IP(dst=host)/scapy.ICMP(type = 8, length = 48)
    
    return m

def network_to_send_traffic(net):
    while True:
        host = random.choice(networks[net])
        mess_type = random.choice(message)
        amount = random.randint(1,10)
        print("Messages: {} , Amount: {}".format(mess_type,amount))
        to_send = packet(mess_type,host)
        if to_send is not None:
            scapy.send(to_send, inter = 0.2 , count = amount)


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

