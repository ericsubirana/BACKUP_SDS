#!/usr/bin/env python3
import time, struct, os
from scapy.all import Ether, IP, UDP, Raw, sendp
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()
INT_PORT = 5001

def build_int_shim():
    hop_count = 1
    ts_ms = int(time.time() * 1000)
    print(f"orig_ts = {ts_ms} ms")
    return bytes([hop_count]) + struct.pack('!Q', ts_ms)

def send_int_packet(dst_ip, iface):
    shim = build_int_shim()
   
    key = os.getenv("AES_KEY").encode()  # Must be 16, 24, or 32 bytes
    if len(key) not in (16, 24, 32):
        raise ValueError("AES_KEY must be 16/24/32 bytes")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, shim, None)  # ciphertext + tag

    payload = b'HELLO-INT'
    full_payload = nonce + ct + payload

    pkt = Ether() / IP(dst=dst_ip) / UDP(sport=5000, dport=INT_PORT) / Raw(full_payload)
    sendp(pkt, iface=iface, verbose=False)
    print(f"Sent encrypted INT packet to {dst_ip} via {iface}")

if __name__ == "__main__":
    send_int_packet(dst_ip="10.0.0.2", iface="h3-eth0")
