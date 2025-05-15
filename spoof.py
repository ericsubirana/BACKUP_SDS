import socket  
import datetime
import time
import sys
import random

# ha de coincidir amb es que posam a mySwitch i a /etc/telegraf/telegraf.conf: "service_address = "udp://:8094"
UDP_IP = "127.0.0.1"
UDP_PORT = 8094

def fake_msg(datapath, in_port, eth_dst, out_port, packets, bytes_):  #crea el mensaje falso
    timestamp = int(datetime.datetime.now().timestamp() * 1e9) #nanoseconds

    msg = f'flows,datapath={datapath} in-port={in_port},eth-dst="{eth_dst}",out-port={out_port},packets={packets},bytes={bytes_} {timestamp}'

    return msg

def send_msg (message, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (ip, port))
    print("msg sent")

if len(sys.argv) < 2 or sys.argv[1] not in ("1", "2"):
    print("Usage: python3 spoof.py <mode>")
    print("        1 = send data that does NOT match the real network")
    print("        2 = send fully random data (some fields may match by chance)")
    sys.exit(1)

mode = sys.argv[1]

while True:
    #random variables para todo
    datapath = random.randint(1, 100)
    in_port = random.randint(1, 10)
    out_port = random.randint(1, 10)
    mac_last_byte = random.randint(1, 255)
    eth_dst = f"00:00:00:00:00:{mac_last_byte:02x}"
    packets = random.randint(1000, 20000)
    bytes_ = random.randint(100000, 8000000)

    if mode == "1": #no arquitectura real
        while datapath in (1, 2):
            datapath = random.randint(3, 100)
        while mac_last_byte in range(1, 9):
            mac_last_byte = random.randint(9, 255)
        eth_dst = f"00:00:00:00:00:{mac_last_byte:02x}"
        while in_port in range(1, 5):
            in_port = random.randint(5, 10)
        while out_port in range(1, 5):
            out_port = random.randint(5, 10)
    
    message = fake_msg(datapath, in_port, eth_dst, out_port, packets, bytes_)
    print (message)
    send_msg(message, UDP_IP, UDP_PORT)
    time.sleep(10)