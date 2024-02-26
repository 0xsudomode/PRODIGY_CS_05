#!/usr/bin/python

# Task 5 : A basic Packet Sniffer [For educational purposes only]

from scapy.all import *

def packet_handler(pkt):
    try:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        payload = pkt[Raw].load.hex() if Raw in pkt else None

        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Protocol:", protocol)
        if payload:
            print("Payload:", payload)

        print("=" * 50)

    except Exception as e:
        print("Exception:", e)

def main():
    print("Sniffing started...")
    try:
        sniff(prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("Sniffing stopped.")

if __name__ == "__main__":
    main()
