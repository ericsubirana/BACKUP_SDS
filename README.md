![diagrama](https://github.com/user-attachments/assets/ee58a51d-09d2-44f4-b68d-baa84a024e69)


# Telemetry Spoofing Attack: 

This project shows how to spoof telemetry data inside a Mininet network. It includes a custom spine-leaf topology, a Ryu controller, and a simple Python script that sends fake flow stats to Telegraf. The goal is to simulate how telemetry systems can be tricked by injecting false data.

## Repository Contents
```
├── spoof.py              # Script to generate and send fake telemetry messages to Telegraf.
├── mySwitch.py           # Ryu controller app that sends real telemetry data to Telegraf.
└── myTopo.py             # Mininet topology definition (spine-and-leaf).
```
## Prerequisites

* **Python 3.8+** with required modules (see `requirements.txt`)
* **Mininet** installed
* **Ryu SDN framework** installed
* **sudo** access (root privileges)

## Attack Workflow

There are two ways to run the telemetry spoofing workflow:
1. **From your local machine (outside Mininet)**: You run the spoofing script on your actual PC, which sends fake telemetry data directly into telegraf.
2. **From inside the Mininet network**: You run the spoofing script directly on one of the simulated hosts. This simulates a compromised device inside the network sending fake telemetry data.

### Attack Workflow from your Local Machine

1. **Start the Ryu Controller**

   ```bash
   ryu-manager --verbose --ofp-tcp-listen-port 6653 mySwitch.py
   ```

2. **Launch Mininet**

   ```bash
   sudo mn --custom myTopo.py --topo spinenleaf \
       --controller=remote,ip=127.0.0.1,port=6653
   ```

3. **Launch the Telemetry Spoofing Attack**

   ```bash
   python3 spoof.py <mode>
   ```
   Where 'mode' can be:
   * 1: Send data that does NOT match the real network topology (fake but structured).
   * 2: Send fully random data (all fields randomized, more noisy).

4. **Observe in InfluxDB or Telegraf the Fake data**


### Attack Workflow from inside the Mininet Network

Mininet hosts are isolated by default, so they can’t talk to your real PC. Creating a bridge and using NAT lets those hosts send data through your PC’s network. That way, your spoofed telemetry from Mininet can actually reach Telegraf running on your machine.

1. **Set up bridge and tap interfaces on the host machine**

   ```bash
   sudo ip link add name br1 type bridge
   sudo ip link set br1 up
   sudo ip tuntap add mode tap user $USER name tap0
   sudo ip link set tap0 master br1
   sudo ip link set tap0 up
   sudo ip addr add 192.168.100.1/24 dev br1
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o <your internet interface> -j MASQUERADE
   ```

2. **Change the UDP IP from 'mySwitch.py', 'myTopo.py', 'spoof.py' from '127.0.0.1' to your host machine's IP address**

3. **Launch Mininet with NAT enabled**

   ```bash
   sudo mn --custom myTopo.py --topo spinenleaf \
       --controller=remote,ip=127.0.0.1,port=6653 --nat
   ```

4. **Attach the tap interface to the Mininet host and configure its network**

   ```bash
   mininet> py from mininet.link import Intf; Intf('tap0', node=net.get('h8'))
   mininet> h8 ifconfig tap0 192.168.100.2/24 up
   mininet> h8 route add default gw 192.168.100.1
   ```

5. **Launch the Telemetry Spoofing Attack inside the host 8**

   ```bash
   mininet> h8 python3 spoof.py <mode>
   ```
   Where 'mode' can be:
   * 1: Send data that does NOT match the real network topology (fake but structured).
   * 2: Send fully random data (all fields randomized, more noisy).

6. **Observe in InfluxDB or Telegraf the Fake data**

## Cleanup

Press `Ctrl+C` in the `spoof.py` terminal to stop the Telemetry Spoofing Attack. 

In InfluxDB execute 'DROP MEASUREMENT flows' to delete the metrics collected.

# Telemetry Spoofing Attack MITIGATION: 
The mitigation method used is the concactenation of a HMAC with the original telemetry message bound to Telegraf. A script named validator recieves the data and if the HMAC concatenated is correct, it is delivered to Telegraf. The connection between the script and Telegraf is protected via TLS protocol. Telegraf authenticates via credentials to the database. Even though the first step (HMAC) solves the problem in case of an attack which comes from a remote host, we decided to also protect the connection of the Script -> Telegraf and Telegraf -> InfluxDb in case there is an internal attacker. 

1. **Start the Modified Ryu Controller**
 
 ```bash
   ryu-manager --verbose --ofp-tcp-listen-port 6653 mySwitchAuth.py
   ```

The UDP_IP and UDP_PORT values have to be changed. Now represent the IP and PORT where the validation script is listening.

2. **Launch Mininet**

```bash
   sudo mn --custom myTopo.py --topo spinenleaf \
       --controller=remote,ip=127.0.0.1,port=6653
   ```

2. **Launch Validation Script**

```bash
   sudo python3 validator.py
   ```

The UDP_IP_PROXY and UDP_PORT_PROXY values have to be the same as the ones specified in the RYU controller. The IP and PORT of the Telegraf agent can be configured aswell. By default Telegraf listens in 127.0.0.1:8094. The IP of the script (Proxy) will be the one of the host machine (not localhost) in the case we want to test and external attack, because otherwise h8 would not be able to find it.

3. **Change configuration of InfluxDB**

```bash
   sudo nano /etc/influxdb/influxdb.conf
   ```

In the http part of the configuration file the two following lines have to be added:
   - bind-address = "127.0.0.1:8086"
   - auth-enabled = true
    
Afterwards, a new user and a password have to be created in InfluxDB. It can be created with the following command.

CREATE USER ryu WITH PASSWORD 'strong_password'
GRANT ALL ON RYU TO ryu

4. **Change configuration of Telegraf**

```bash
   sudo nano /etc/telegraf/telegraf.conf
   ```
The output configuration part has to be like the following:

[[outputs.influxdb]]

urls = ["http://127.0.0.1:8086"]

database = "RYU"

username = "ryu"

password = "strong_password"

The output input configuration part has to be like the following:

[[inputs.socket_listener]]

service_address = "tcp://127.0.0.1:8094"

tls_cert = "/home/vboxuser/Desktop/proj/BACKUP_SDS/telegraf.crt"           Here you put the path to the actual location of your files!

tls_key = "/home/vboxuser/Desktop/proj/BACKUP_SDS/telegraf.key"            Here you put the path to the actual location of your files!

tls_allowed_cacerts = ["/home/vboxuser/Desktop/proj/BACKUP_SDS/ca.crt"]    Here you put the path to the actual location of your files!

data_format="influx"

5. **Launch the Telemetry Spoofing Attack**

   ```bash
   python3 spoof.py <mode>
   ```
   Where 'mode' can be:
   * 1: Send data that does NOT match the real network topology (fake but structured).
   * 2: Send fully random data (all fields randomized, more noisy).

6. **Observe the failure of the attack**

You can see that the attack does not work anymore by checking the logs of the verification script. If you still not trust that the attack is mitigated, you can see the contents of the database.

**Attack from inside/outside the Mininet**

Check the "Attack Workflow from inside the Mininet Network" part of the ReadMe file in the case where you want to perform the attack from a host inside the Mininet.


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
# INT False-Latency MITM Attack MITIGATION

In order to mitigate the attack INT False-Latency we've implemented two different security features:
* Encryption of the INT data
* Mitigating ARP-Spoofing

## Encryption of the INT data

There are two new scripts using AES-CGM encryption algorithm:
* get_timestamp_int_protected.py
* send_int_protected.py

You will have to create a .env file with the following content:

```bash
   AES_KEY = a key for encryption of 16,24 or 32 bytes of length
   ```

In order to use them follow the following workflow

### Attack Workflow

1. **Start the Ryu Controller**

   ```bash
   ryu-manager --verbose --ofp-tcp-listen-port 6653 mySwitch.py
   ```

2. **Launch Mininet**

   ```bash
   sudo mn --custom myTopo.py --topo spinenleaf \
       --controller=remote,ip=127.0.0.1,port=6653 --link tc
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
   h2$ python3 get_timestamp_int_protected.py
   ```

   This script listens for incoming INT packets on UDP port 5001 and prints out the hop count and timestamp fields.

6. **Send an INT Packet from h3**

   In the `h3` xterm:

   ```bash
   h3$ python3 send_int_protected.py
   ```

   This script crafts and sends a single INT packet (UDP port 5001) with a hop count and current timestamp.

7. **Observe Correct Latency**

   * On `h2`, the timestamp printed will reflect the original timestamp
   * In the Mininet CLI will be reflected some numbers with any sense (encrypted)

## Mitigating ARP-Spoofing

   Before exchanging INT data run anti_arp_spoofing_rules.py in order to modify swtches rules to allow only trusted IP/MAC pairs

   Before step 5 of the previous workflow, execute this command on an extra terminal:

   ```bash
   sudo python3 anti_arp_spoofing_rules.py 
   ```

   Now, In the Mininet CLI the attack is not going to be working anymore 


**Note:** This code is for educational purposes only. Always obtain proper authorization before testing on live networks.

