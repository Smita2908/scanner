Purpose
To scan the network and find the information regarding connected devices using ARP, DHCP and UPnP and also sniff DNS and HTTP packets.

Dependencies
pip install scapy
pip install scapy_http
pip install requests

Usage
sudo python3 scanner.py arp
sudo python3 scanner.py dns
sudo python3 scanner.py upnp
sudo python3 scanner.py http
sudo python3 dhcp_listener.py
sudo pyrhon3 upnp_info.py

Attribution
https://jcutrer.com/python/scapy-dhcp-listener
https://github.com/tenable/upnp_info