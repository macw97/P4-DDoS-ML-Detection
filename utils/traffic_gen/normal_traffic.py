import sys
import os
import random
import scapy.all as scapy 

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
        m = scapy.IP(dst=host)/scapy.TCP(dport=1450)
    elif message_type == "UDP":
        m = scapy.IP(dst=host)/scapy.UDP(dport=1450)
    elif message_type == "ICMP":
        m = scapy.IP(dst=host)/scapy.ICMP()
    
    return m

def network_to_send_traffic(net):
    while True:
        host = random.choice(networks[net])
        mess_type = random.choice(message)
        amount = random.randint(1,15)
        print("Messages: {} , Amount: {}".format(mess_type,amount))
        to_send = packet(mess_type,host)
        if to_send is not None:
            scapy.send(to_send, inter = 0.2 , count = amount)




if __name__ == '__main__':
    try:
        net = sys.argv[1]
    except IndexError as e:
        print("No network ip to send traffic: {}".format(e))
    
    if net in networks:
        network_to_send_traffic(net)
    else:
        print("There is no such network : {}".format(net))

