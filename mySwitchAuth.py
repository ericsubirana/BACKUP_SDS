from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, udp
from ryu.ofproto import inet
import struct
import datetime
import socket
import hmac
import hashlib
import base64

HMAC_KEY = b"secret_key"

UDP_IP = "10.0.2.5"        # IP y puerto donde Telegraf escucha
UDP_PORT = 8095
INT_UDP_PORT       = 5001   # Puerto original de INT
PROCESSED_INT_PORT = 6001   # Puerto “marcado” para paquetes ya procesados

def sign_message(msg: str, key: bytes) -> str:
    mac = hmac.new(key, msg.encode(), hashlib.sha256).digest()
    mac_b64 = base64.b64encode(mac).decode()
    return f"{msg}||{mac_b64}"

class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        # Creamos un socket UDP una vez para enviar mensajes
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.debug('Registrar datapath: %016x', dp.id)
                self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.debug('Eliminar datapath: %016x', dp.id)
                del self.datapaths[dp.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
        datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY))
        
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        for stat in sorted([f for f in ev.msg.body if f.priority == 1],
                        key=lambda f: (f.match['in_port'], f.match['eth_dst'])):
            timestamp = int(datetime.datetime.now().timestamp() * 1e9)
            msg = (
                "flows,datapath=%x in-port=%x,eth-dst=\"%s\","
                "out-port=%x,packets=%d,bytes=%d %d"
            ) % (
                ev.msg.datapath.id,
                stat.match['in_port'],
                stat.match['eth_dst'],
                stat.instructions[0].actions[0].port,
                stat.packet_count,
                stat.byte_count,
                timestamp
            )
            try:
                signed_msg = sign_message(msg, HMAC_KEY)
                self.udp_sock.sendto(signed_msg.encode(), (UDP_IP, UDP_PORT))
            except Exception as e:
                self.logger.error(f"Error al enviar UDP flow stats: {e}")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        for stat in sorted(ev.msg.body, key=attrgetter('port_no')):
            timestamp = int(datetime.datetime.now().timestamp() * 1e9)
            msg = (
                "ports,datapath=%x,port=%x rx-pkts=%d,rx-bytes=%d,"
                "rx-error=%d,tx-pkts=%d,tx-bytes=%d,tx-error=%d %d"
            ) % (
                ev.msg.datapath.id,
                stat.port_no,
                stat.rx_packets,
                stat.rx_bytes,
                stat.rx_errors,
                stat.tx_packets,
                stat.tx_bytes,
                stat.tx_errors,
                timestamp
            )
            try:
                signed_msg = sign_message(msg, HMAC_KEY)
                self.udp_sock.sendto(signed_msg.encode(), (UDP_IP, UDP_PORT))
            except Exception as e:
                self.logger.error(f"Error al enviar UDP port stats: {e}")
            
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        match_raw = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=INT_UDP_PORT)
        inst_raw  = [parser.OFPInstructionActions(
                          ofp.OFPIT_APPLY_ACTIONS,
                          [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                      )]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=200,
                                      match=match_raw, instructions=inst_raw))

        match_marked = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=PROCESSED_INT_PORT)
        inst_marked  = [parser.OFPInstructionActions(
                             ofp.OFPIT_APPLY_ACTIONS,
                             [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                         )]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=200,
                                      match=match_marked, instructions=inst_marked))

        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0,
                                      match=parser.OFPMatch(),
                                      instructions=[parser.OFPInstructionActions(
                                          ofp.OFPIT_APPLY_ACTIONS,
                                          [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                                      )]))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _int_packetin_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        parser  = dp.ofproto_parser

        pkt     = packet.Packet(msg.data)
        eth     = pkt.get_protocol(ethernet.ethernet)
        ip4     = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not (ip4 and udp_pkt and udp_pkt.dst_port == INT_UDP_PORT):
            return

        payload   = pkt.protocols[-1]
        hop_count = payload[0]
        orig_ts   = struct.unpack('!Q', payload[1:9])[0]
        new_ts    = orig_ts

        self.logger.info(
            "INT shim | dpid=%s hop=%s ts=%d",
            format(dp.id, 'x'), hop_count, new_ts
        )

        new_shim    = bytes([hop_count]) + struct.pack('!Q', new_ts)
        new_payload = new_shim + payload[9:]
        pkt.protocols[-1] = new_payload
        pkt.serialize()

        out_port = self.mac_to_port.get(dp.id, {}).get(eth.dst, dp.ofproto.OFPP_FLOOD)
        actions = [
            parser.OFPActionSetField(udp_dst=PROCESSED_INT_PORT),
            parser.OFPActionOutput(out_port)
        ]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        dp.send_msg(out)

