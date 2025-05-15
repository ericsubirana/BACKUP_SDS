#!/usr/bin/env python3
from scapy.all import sniff, UDP, Raw
import struct, time

def cb(pkt):
    if UDP in pkt and pkt[UDP].dport == 5001 and Raw in pkt:
        now = time.time()
        hop      = pkt[Raw].load[0]
        (ts_int,) = struct.unpack("!Q", pkt[Raw].load[1:9])
        print(f"llegada @ {now:.6f}s  |  hop={hop}  |  ts_int={ts_int}")

sniff(iface="h2-eth0", filter="udp port 5001", prn=cb)
