#!/usr/bin/env python3
import struct, time, os
from scapy.all import sniff, UDP, Raw
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()
key = os.getenv("AES_KEY").encode()

def cb(pkt):
    try:
        if UDP in pkt and pkt[UDP].dport == 5001 and Raw in pkt:
            raw = pkt[Raw].load
            nonce = raw[:12]
            ct = raw[12:-9]  # 9 shim + 8 tag
            payload = raw[-9:]

            aesgcm = AESGCM(key)
            shim = aesgcm.decrypt(nonce, ct, None)

            hop = shim[0]
            (ts_int,) = struct.unpack("!Q", shim[1:])
            now = time.time()
            print(f"VALID @ {now:.6f}s | hop={hop} | ts_int={ts_int} | payload={payload}")
    except Exception as e:
        print("Continue sniffing...")

sniff(iface="h2-eth0", filter="udp port 5001", prn=cb, store = 0)