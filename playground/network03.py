from scapy.all import *
from scapy.layers.l2 import ARP

arp_packet = ARP(pdst="192.168.18.8")
response = sr1(arp_packet, timeout=2)
if response:
    print(response.show())  # Should show details if ARP is successful
