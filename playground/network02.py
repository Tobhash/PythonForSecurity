from scapy.all import *
from scapy.layers.inet import IP, TCP

# Define a TCP SYN packet to check if port 80 is open on Google's server
tcp_packet = IP(dst="8.8.8.8") / TCP(dport=80, flags='S')  # 'S' is the SYN flag

# Send the packet and wait for a single response
response = sr1(tcp_packet, timeout=2)

if response:
    # Print a summary of the response
    print("Received response:", response.summary())

    # Check if there's a TCP layer in the response
    if response.haslayer(TCP):
        tcp_layer = response[TCP]

        # Check the TCP flags
        if tcp_layer.flags & 0x02:  # 0x02 is the SYN flag
            print("Received SYN")
        if tcp_layer.flags & 0x10:  # 0x10 is the ACK flag
            print("Received ACK")
        if tcp_layer.flags & 0x11:  # 0x11 is the FIN/ACK flag
            print("Received FIN/ACK")
else:
    print("No response received")
