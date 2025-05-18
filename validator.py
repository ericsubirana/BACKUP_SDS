import socket
import ssl
import hmac
import hashlib
import base64

UDP_IP_PROXY = "10.0.2.5"
UDP_PORT_PROXY = 8095

TCP_IP_TELEGRAF = "127.0.0.1"
TCP_PORT_TELEGRAF = 8094

SECRET_KEY = b"secret_key"

# TLS Certificates
CERT_FILE = "proxy.crt"
KEY_FILE = "proxy.key"
CA_FILE = "ca.crt"

def verify_hmac(message_bytes, hmac_received_b64):
    h = hmac.new(SECRET_KEY, message_bytes, hashlib.sha256)
    expected_b64 = base64.b64encode(h.digest()).decode()
    return hmac.compare_digest(expected_b64, hmac_received_b64)

def create_tls_connection():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.check_hostname = False  # optional: disable hostname validation

    raw_sock = socket.create_connection((TCP_IP_TELEGRAF, TCP_PORT_TELEGRAF))
    tls_sock = context.wrap_socket(raw_sock, server_hostname=TCP_IP_TELEGRAF)
    return tls_sock

def main():
    sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_recv.bind((UDP_IP_PROXY, UDP_PORT_PROXY))

    print(f"Proxy listening on UDP {UDP_IP_PROXY}:{UDP_PORT_PROXY}")
    tls_sock = None

    while True:
        data, addr = sock_recv.recvfrom(65535)

        try:
            full_msg = data.decode()
            if "||" not in full_msg:
                print(f"Message received without HMAC from {addr}, discarded.")
                continue

            msg, hmac_received = full_msg.rsplit("||", 1)
            msg_bytes = msg.encode()

            if verify_hmac(msg_bytes, hmac_received):
                print(f"Valid message from {addr}: {msg}...")

                try:
                    # Reconnect if needed
                    if tls_sock is None:
                        tls_sock = create_tls_connection()

                    tls_sock.sendall(msg_bytes + b"\n")  # Telegraf expects newline-delimited lines

                except (ssl.SSLError, OSError) as e:
                    print(f"TLS error, retrying connection: {e}")
                    tls_sock = None  # force reconnect

            else:
                print(f"Invalid HMAC from {addr}, message discarded.")

        except Exception as e:
            print(f"Error processing message from {addr}: {e}")

if __name__ == "__main__":
    main()

