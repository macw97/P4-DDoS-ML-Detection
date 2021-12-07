import os
import sys
import random
from normal_traffic import networks
iperf_type = {
    "tcp" : "-t",
    "udp" : "-u"
    }
bandwidth = ["5M","10M","50M","100M"]

def traffic(type_of_traffic,port,network):
    target_host = random.choice(networks[network])
    os.system("iperf -c {} {} -b {} -p {}".format(target_host,type_of_traffic,random.choice(bandwidth),port))


if __name__ == '__main__':
    try:
        typeof = sys.argv[1]
    except IndexError as e:
        print("Choose if tcp or udp iperf traffic: {}".format(e))
        exit(0)

    try:
        port = sys.argv[2]
    except IndexError as e:
        print("Port not provided: {}".format(e))
        exit(0)

    if typeof in iperf_type:
        traffic(typeof,port,"10.0.1.0")
