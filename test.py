#!/usr/bin/python3
import ipaddress
network = ipaddress.ip_network("192.168.1.0/24").hosts()
used_address_list = ["192.168.1.1","192.168.1.2","192.168.1.3","192.168.1.4"]

#print(ipaddress.ip_address('192.168.0.1'))
for i in network:
    if str(i) not in used_address_list:
        print(i)
        break