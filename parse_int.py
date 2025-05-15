#!/usr/bin/env python3
import struct
from scapy.all import rdpcap, Raw

def main():
    pcap_file = '/tmp/int_out.pcap'
    try:
        pkts = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: {pcap_file} not found")
        return
    if not pkts:
        print("No packets in pcap")
        return

    p = pkts[0]
    if Raw not in p:
        print("No Raw payload in first packet")
        return

    data = p[Raw].load
    hop      = data[0]
    reported = struct.unpack('!Q', data[1:9])[0]

    print(f"Hop count: {hop}")
    print(f"Reported ingress timestamp: {reported} ms")

if __name__ == '__main__':
    main()
