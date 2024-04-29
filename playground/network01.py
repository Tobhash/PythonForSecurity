from scapy.all import *
from scapy.layers.inet import IP, ICMP

# Define an ICMP "echo request" (ping) packet
icmp_packet = IP(dst="192.168.18.10") / ICMP()

# Send the packet and wait for a single response with a 2-second timeout
response = sr1(icmp_packet, timeout=2)

if response:
    print("Received response:", response.summary())
else:
    print("No response received")
