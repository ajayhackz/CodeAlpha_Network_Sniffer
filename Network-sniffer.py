from scapy.all import *

def packet_handler(packet):
    print("---------------------------------------------------------")

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")

sniff(prn=packet_handler, filter="ip")
