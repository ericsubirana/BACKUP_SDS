#!/usr/bin/env python3
import time, struct
from scapy.all import Ether, IP, UDP, Raw, sendp

INT_PORT = 5001

def build_int_shim():
    # 1 byte: hop-count (we start at 1)
    # 8 bytes: current timestamp in ms
    hop_count = 1
    ts_ms     = int(time.time() * 1000)
    # print the original timestamp before sending
    print(f"orig_ts = {ts_ms} ms")
    return bytes([hop_count]) + struct.pack('!Q', ts_ms)

def send_int_packet(dst_ip, iface):
    shim = build_int_shim()
    payload = b'HELLO-INT'
    pkt = (
        Ether() /
        IP(dst=dst_ip) /
        UDP(sport=5000, dport=INT_PORT) /
        Raw(shim + payload)
    )
    sendp(pkt, iface=iface, verbose=False)
    print(f"Sent INT packet to {dst_ip} via {iface}")

if __name__ == "__main__":
    # adjust dst and iface as needed
    send_int_packet(dst_ip="10.0.0.2", iface="h3-eth0")
