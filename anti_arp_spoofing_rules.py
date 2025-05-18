
import os

# Hosts conectados a cada leaf
leaf_hosts = {
    's3': [1, 2],
    's4': [3, 4],
    's5': [5, 6],
    's6': [7, 8],
}

switches = ['s1', 's2', 's3', 's4', 's5', 's6']

# 1. Limpiar reglas
for sw in switches:
    print(f"[{sw}] Limpiando reglas")
    os.system(f"sudo ovs-ofctl -O OpenFlow13 del-flows {sw}")

# 2. En leafs: validar IP/MAC y permitir tráfico legítimo
for sw, hosts in leaf_hosts.items():
    for h in hosts:
        ip = f"10.0.0.{h}"
        mac = f"00:00:00:00:00:{h:02x}"
        port = hosts.index(h) + 1  # Asume que el primer host está en el puerto 1, etc.
        # Permitir solo IP/ARP legítimos desde el puerto del host
        os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} "
                  f"\"priority=100,in_port={port},ip,ip_src={ip},dl_src={mac},actions=NORMAL\"")
        os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} "
                  f"\"priority=100,in_port={port},arp,arp_spa={ip},arp_sha={mac},actions=NORMAL\"")
        # Permitir tráfico de retorno hacia el host por su MAC y puerto
        os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} "
                  f"\"priority=90,dl_dst={mac},actions=output:{port}\"")
    # Permitir flooding ARP para descubrimiento
    os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} "
              f"\"priority=10,arp,actions=FLOOD\"")
    # Bloquear todo lo demás
    os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} \"priority=0,actions=drop\"")

# 3. En switches intermedios (core/agg): permitir forwarding general
for sw in ['s1', 's2']:
    # Permitir forwarding de todo el tráfico IP y ARP entre puertos
    os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} "
              f"\"priority=10,ip,actions=NORMAL\"")
    os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} "
              f"\"priority=10,arp,actions=FLOOD\"")
    # Bloquear todo lo demás
    os.system(f"sudo ovs-ofctl -O OpenFlow13 add-flow {sw} \"priority=0,actions=drop\"")