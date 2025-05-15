![image](https://github.com/user-attachments/assets/b55b41fb-e33e-4819-a3de-7988e5adfed3)

1. Modificar el fitxer `/etc/telegraf/telegraf.conf`:
   - Canviar la línia següent: 
   ```
   service_address = "udp://:8094
   ```

2. (necessitam 3 terminals: A,B,C) A la terminal A executar:
   ```
   sudo systemctl restart telegraf
   sudo systemctl status telegraf
   sudo systemctl start influxdb
   ```
   
3. A la terminal B:
   ```
   ryu-manager --verbose --ofp-tcp-listen-port 6653 mySwitch.py
   ```

4. A la terminal C:
   ```
   sudo mn --custom myTopo.py --topo spinenleaf --controller=remote,ip=127.0.0.1,port=6653
   ```

# ATAC TELEMETRY SPOOFING: 
Obrim una nova terminal (de moment per saber q funciona, després implementar als hosts):
   ```python3 spoof.py argument```

(argument 1 si volem que els arguments no coincideixin amb l'arquitectura o argument 2 si les volem completament random)


# INT False-Latency MITM Attack

This project demonstrates an INT (In-band Network Telemetry) false-latency man-in-the-middle (MITM) attack. It uses a Ryu controller application, a custom Mininet topology, and a Scapy-based MITM script to intercept and modify INT shim headers by adding artificial delay.

## Repository Contents

```
├── delay_attack.sh       # Script to set up forwarding, ARP spoofing, and run the MITM
├── get_timestamp_int.py  # Script for h2 to listen for INT packets and print timestamps
├── send_int.py           # Script for h3 to send INT packets
├── mySwitch.py           # Ryu controller application for intercepting INT
├── myTopo.py             # Mininet topology definition (spine-and-leaf)
├── parse_int.py          # (Optional) Parser for INT shim payloads
└── requirements.txt      # Python dependencies
```

## Prerequisites

* **Python 3.8+** with required modules (see `requirements.txt`)
* **Mininet** installed
* **Ryu SDN framework** installed
* **scapy** and **arpspoof** utilities
* **sudo** access (root privileges)

Install Python dependencies:

```bash
pip3 install -r requirements.txt
```

## Attack Workflow

1. **Start the Ryu Controller**

   ```bash
   ryu-manager --verbose --ofp-tcp-listen-port 6653 mySwitch.py
   ```

2. **Launch Mininet**

   ```bash
   sudo mn --custom myTopo.py --topo spinenleaf \
       --controller=remote,ip=127.0.0.1,port=6653
   ```

3. **Open Host Terminals**

   In the Mininet CLI, open xterms for `h2` and `h3`:

   ```bash
   mininet> xterm h2 h3
   ```

4. **Launch the MITM Attack on h1**

   In the Mininet CLI, run:

   ```bash
   mininet> h1 ./delay_attack.sh
   ```

   This will:

   * Apply a real delay (`tc netem`) on `h1-eth0`
   * ARP-spoof h2⇄h3 so traffic is redirected through `h1`
   * Drop kernel-forwarded INT packets via `iptables`
   * Launch the Scapy MITM script to inject fake delay into INT shim headers

5. **Receive and Display INT Packets on h2**

   In the `h2` xterm:

   ```bash
   h2$ python3 get_timestamp_int.py
   ```

   This script listens for incoming INT packets on UDP port 5001 and prints out the hop count and timestamp fields.

6. **Send an INT Packet from h3**

   In the `h3` xterm:

   ```bash
   h3$ python3 send_int.py
   ```

   This script crafts and sends a single INT packet (UDP port 5001) with a hop count and current timestamp.

7. **Observe False Latency**

   * On `h2`, the timestamp printed will reflect the original timestamp plus the fake delay.
   * Use Wireshark (optional) on `h2-eth0` to inspect the INT shim header and verify the high-bit marker.

## Cleanup

Press `Ctrl+C` in the `delay_attack.sh` terminal to stop the MITM script. The cleanup routine will:

* Remove `tc` delay
* Delete the `iptables` rule
* Kill ARP spoofing processes
* Remove temporary Python script

---

**Note:** This code is for educational purposes only. Always obtain proper authorization before testing on live networks.

