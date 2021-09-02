#!/usr/bin/python3

import argparse
from scapy.all import *
from netaddr import IPNetwork
from threading import Thread

parser = argparse.ArgumentParser()
parser.add_argument('-subnet', dest='subnet', help='ARP Scanner!', required=True)
parsed_args = parser.parse_args()

subnet = parsed_args.subnet

print('Starting ARP scan for', subnet)

def arp_request(ip):
    arp_request = ARP()
    arp_request.pdst = ip

    arp_response = sr1(arp_request, timeout=5, verbose=0)

    if arp_response:
        print('{:<16} -> {}'.format(ip, arp_response.hwsrc))
    else:
        pass

for ip in IPNetwork(subnet):
    ip_ = str(ip)
    Thread(target=arp_request, args={ip_}).start()




