from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import in_proto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.lib import hub

from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu.topology import switches
from ryu.topology import api
from collections import defaultdict

import random
import itertools
import time

# switches
switches = []

# mymac[srcmac]->(switch, port)
mymac = {}

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))
delay = defaultdict(lambda: defaultdict(lambda: 0))

def minimum_distance(distance, Q):
    min = float('Inf')
    node = 0
    for v in Q:
        if distance[v] < min:
            min = distance[v]
            node = v
    return node

def get_path(src, dst, first_port, final_port):
    # Dijkstra's algorithm
    print "get_path is called, src=%s dst=%s first_port=%s final_port=%s" % (
        src, dst, first_port, final_port)

    distance = defaultdict(lambda: float('Inf'))
    previous = defaultdict(lambda: None)

    distance[src] = 0
    Q = set(switches)

    while len(Q) > 0:
        u = minimum_distance(distance, Q)
        Q.remove(u)

        for p in switches:
            if adjacency[u][p] != None:
                # print p
                w = delay[u][p]
                if distance[u] + w < distance[p]:
                    distance[p] = distance[u] + w
                    previous[p] = u

    r = []
    p = dst
    r.append(p)
    q = previous[p]
    while q is not None:
        if q == src:
            r.append(q)
            break
        p = q
        r.append(p)
        q = previous[p]

    r.reverse()
    if src == dst:
        path = [src]
    else:
        path = r

    # Now add the ports
    r = []
    in_port = first_port
    for s1, s2 in zip(path[:-1], path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1]
    r.append((dst, in_port, final_port))
    return r

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)

        # maps a mac to its port in switch
        self.mac_to_port = {}

        # ryu datapath object of switch
        self.datapath_list = {}

        # Maps an IP address to the corresponding MAC address
        self.arp_table = {}

        # Fake addresses only known to the controller
        self.controller_ip = "10.0.0.100"
        self.controller_mac = "dd:dd:dd:dd:dd:df"
        self.ping_mac = "de:dd:dd:dd:de:dd"
        self.ping_ip = "10.0.0.99"

        self.replied = []

    def monitor_link(self, s1, s2):
        '''
            Monitors link latency between two switches.
            Sends ping packet every 0.5 second.
        '''
        while True:
            self.send_ping_packet(s1, s2)

            hub.sleep(0.5)

        self.logger.info('Stop monitoring link %s %s' % (s1.dpid, s2.dpid))

    def send_ping_packet(self, s1, s2):
        '''
            Send a ping/ICMP packet between two switches.
            Uses ryu's packet library.
            Uses a fake MAC and IP address only known to controller.
        '''
        datapath = self.datapath_list[int(s1.dpid)]
        dst_mac = self.ping_mac
        dst_ip = self.ping_ip
        out_port = s1.port_no
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,
                                           src=self.controller_mac,
                                           dst=dst_mac))
        pkt.add_protocol(ipv4.ipv4(proto=in_proto.IPPROTO_ICMP,
                                   src=self.controller_ip,
                                   dst=dst_ip))
        echo_payload = '%s;%s;%f' % (s1.dpid, s2.dpid, time.time())
        payload = icmp.echo(data=echo_payload)
        pkt.add_protocol(icmp.icmp(data=payload))
        pkt.serialize()

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            data=pkt.data,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions
        )

        datapath.send_msg(out)

    def ping_packet_handler(self, pkt):
        '''
            Handler function when ping packet arrives.
            Extracts the data from the packet and calculates the latency.
        '''
        icmp_packet = pkt.get_protocol(icmp.icmp)
        echo_payload = icmp_packet.data
        payload = echo_payload.data
        info = payload.split(';')
        s1 = info[0]
        s2 = info[1]
        latency = (time.time() - float(info[2])) * 1000  # in ms
        # print "s%s to s%s latency = %f ms" % (s1, s2, latency)
        delay[int(s1)][int(s2)] = latency

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, instructions=inst)
        datapath.send_msg(mod)

    def install_path(self, ev, p, src_ip, dst_ip):
        '''
            Install openflow rules using IP addresses for routing
        '''
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        for sw, in_port, out_port in p:
            # print src_ip, "->", dst_ip, "via ", sw, " out_port=", out_port
            match_ip = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
            )
            match_arp = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_spa=src_ip,
                arp_tpa=dst_ip
            )
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[int(sw)]
            self.add_flow(datapath, 1, match_ip, actions)
            self.add_flow(datapath, 1, match_arp, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        # print pkt
        if ipv6_pkt:  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            self.add_flow(datapath, 1, match, [])
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if dst == self.ping_mac:
            # ping packet arrives
            self.ping_packet_handler(pkt)
            return

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if src not in mymac.keys():
            mymac[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                path = get_path(mymac[src][0], mymac[dst][
                                0], mymac[src][1], mymac[dst][1])
                reverse = get_path(mymac[dst][0], mymac[src][
                                    0], mymac[dst][1], mymac[src][1])
                print path
                self.install_path(ev, path, src_ip, dst_ip)
                self.install_path(ev, reverse, dst_ip, src_ip)
                out_port = path[0][2]
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    dst_mac = self.arp_table[dst_ip]
                        # always try to reply arp requests first
                    path = get_path(mymac[src][0], mymac[dst_mac][
                                0], mymac[src][1], mymac[dst_mac][1])
                    reverse = get_path(mymac[dst_mac][0], mymac[src][
                                        0], mymac[dst_mac][1], mymac[src][1])
                    print path
                    self.install_path(ev, path, src_ip, dst_ip)
                    self.install_path(ev, reverse, dst_ip, src_ip)
                    out_port = path[0][2]

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def _switch_enter_handler(self, ev):
        switch = ev.switch.dp
        if switch.id not in switches:
            switches.append(switch.id)
            self.datapath_list[switch.id] = switch

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        adjacency[s1.dpid][s2.dpid] = s1.port_no
        adjacency[s2.dpid][s1.dpid] = s2.port_no
        hub.spawn(self.monitor_link, s1, s2)