# import sys
import json
import socket
import argparse
import os
try:
    import requests  # ModuleNotFoundError: No module named 'requests'
except ModuleNotFoundError:
    os.system('pip install requests')


parser = argparse.ArgumentParser(description='Grab IP information')
parser.add_argument('-hostname', dest='hostname', help='hostname to grab information', required=True)
parsed_args = parser.parse_args()


hostname = parsed_args.hostname


host_ip = socket.gethostbyname(hostname)
print('[INFO] - ' + hostname + ' -> ' + host_ip)
third_party = 'https://ipinfo.io/{host_ip}/json'
url = third_party.format(host_ip=host_ip)
response = requests.get(url)
host_info_str = response.text
# print(host_info_str)


f = '\t{:<10}:\t{}'
host_info = json.loads(host_info_str)
print('[INFO] - Get information using third-party: ' + url)
for info_arg_name in host_info:
    print(f.format(info_arg_name, host_info[info_arg_name]))






