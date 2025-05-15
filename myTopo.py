#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections
from mininet.cli import CLI

CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6653

class SpineLeafTopo(Topo):
    def build(self):
        # Add spine switches
        spines = [ self.addSwitch('s{}'.format(i), protocols='OpenFlow13')
           for i in (1, 2) ]
        # Add leaf switches
        leafs = [self.addSwitch('s{}'.format(i), protocols='OpenFlow13') for i in (3, 4, 5, 6)]
        # Add hosts
        # Add hosts with fixed MACs and IPs
        hosts = [ self.addHost('h{}'.format(j),
                       mac='00:00:00:00:00:{:02x}'.format(j),
                       ip='10.0.0.{}'.format(j) + '/8')
          for j in range(1, 9) ]
        # Connect 2 hosts to each leaf
        for idx, leaf in enumerate(leafs):
            self.addLink(hosts[2*idx], leaf, bw=100)
            self.addLink(hosts[2*idx+1], leaf, bw=100)
        # Connect each leaf to both spines (full spine-leaf, loops present)
        for i, leaf in enumerate(leafs):
            spine = spines[0] if i < 2 else spines[1]
            self.addLink(leaf, spine, bw=10)
        # connect s1 with s2
        self.addLink(spines[0], spines[1], bw=10)

if __name__ == '__main__':
    setLogLevel('info')
    topo = SpineLeafTopo()
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoStaticArp=True
    )
    # Add remote controller
    net.addController(
        'c0',
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT
    )
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")
    # net.pingAll()
    CLI(net)
    net.stop()


topos = { 'spinenleaf': (lambda: SpineLeafTopo()) }