from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
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

from ryu.topology import event
from ryu.topology import switches
from collections import defaultdict
from requests import get
from subprocess import check_output
from operator import itemgetter
import logging
import socket
import time
import os
import re
import shlex
import time

# switches
switches = []

switch_info = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: 0)))

ifindex = {}

# mymac[srcmac]->(switch, port)
mymac = {}

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))
traffic = defaultdict(lambda: defaultdict(lambda: 0))

collector = '127.0.0.1'

def getIfInfo(ip):
    '''
    Get interface name of ip address (collector)
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, 0))
    ip = s.getsockname()[0]
    ifconfig = check_output(['ifconfig'])
    ifs = re.findall(r'^(\S+).*?inet addr:(\S+).*?', ifconfig, re.S | re.M)
    for entry in ifs:
        if entry[1] == ip:
            return entry

def init_sflow(ifname, collector, sampling, polling):
    '''
    Initialise sFlow for monitoring traffic
    '''
    cmd = shlex.split('ip link show')
    out = check_output(cmd)
    info = re.findall('(\d+): ((s[0-9]+)-eth([0-9]+))', out)

    sflow = 'ovs-vsctl -- --id=@sflow create sflow agent=%s target=\\"%s\\" sampling=%s polling=%s --' % (
        ifname, collector, sampling, polling)

    for ifindex, ifname, switch, port in info:
        if int(switch[1:]) in switches:
            switch_info[int(switch[1:])][int(port)]['ifindex'] = ifindex
            sflow += ' -- set bridge %s sflow=@sflow' % switch

    print sflow
    # os.system(sflow)

def monitor_link(s1, s2):
    '''
    Measure outgoing traffic per second for all switch ports
    '''
    while True:
        url = 'http://' + collector + ':8008/metric/' + \
            collector + '/' + str(switch_info[s1.dpid][int(s1.port_no)]['ifindex']) + \
            '.ifoutoctets/json'
        r = get(url)
        response = r.json()
        print response
        # Bps to Kbps
        traffic[s1][s2] = response[0]['metricValue'] * 8 / 1000
        print traffic[s1][s2]

        hub.sleep(0.3)  

def minimum_cost(cost, Q):
    min = float('Inf')
    node = 0
    for v in Q:
        if cost[v] < min:
            min = cost[v]
            node = v
    return node

def get_path(src, dst, first_port, final_port):
    '''
        Thanks to Dr. Chih-Heng Ke of NQU Taiwan
        http://csie.nqu.edu.tw/smallko/sdn/sdn.htm
        Find shortest path between two switches
        using Dijkstra's algorithm.
    '''
    # print "get_path is called, src=%s dst=%s first_port=%s final_port=%s" % (
    #     src, dst, first_port, final_port)
    cost = defaultdict(lambda: float('Inf'))
    previous = defaultdict(lambda: None)

    cost[src] = 0
    Q = set(switches)

    while len(Q) > 0:
        u = minimum_cost(cost, Q)
        Q.remove(u)

        for p in switches:
            if adjacency[u][p] != None:
                # print p
                w = traffic[u][p]
                if cost[u] + w < cost[p]:
                    cost[p] = cost[u] + w
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
    return r, cost[dst]

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

        # Servers to load-balance
        self.servers = [
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3"
        ]

        # Virtual addresses for clients to access load-balanced servers
        self.virtual_ip = "10.0.0.20"
        self.virtual_mac = "dd:dd:dd:dd:dd:dd"

        # Fake addresses only known to the controller
        self.controller_ip = "10.0.0.100"
        self.controller_mac = "dd:dd:dd:dd:dd:df"
        self.ping_mac = "de:dd:dd:dd:de:dd"
        self.ping_ip = "10.0.0.99"

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

        # server discovery
        for server in self.servers:
            dst = mac.BROADCAST_STR
            src = self.controller_mac
            dst_ip = server
            src_ip = self.controller_ip
            opcode = arp.ARP_REQUEST
            port = ofproto.OFPP_FLOOD
            self.send_arp(datapath, dst, src, dst_ip, src_ip, opcode, port)

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

    def send_arp(self, datapath, eth_dst, eth_src, dst_ip, src_ip, opcode, port):
        ''' Send ARP Packet. '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        arp_packet = packet.Packet()

        arp_packet.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_dst,
            src=eth_src))
        arp_packet.add_protocol(arp.arp(
            opcode=opcode,
            src_mac=eth_src,
            src_ip=src_ip,
            dst_mac=eth_dst,
            dst_ip=dst_ip))

        arp_packet.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=arp_packet.data)
        datapath.send_msg(out)

    def load_balancing_handler(self, ev, eth, pkt, in_port):
        '''
            Load balancing handler:
            Installs a route to one of the available servers
            using dijkstra's algorithm costs for selection.
            Modifies the virtual address to the chosen server.
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        try:
            src_ip = pkt.src_ip
        except:
            src_ip = pkt.src

        selected_server_ip = None
        minimum = float('Inf')
        path = []
        for server in self.servers:
            ip_server = server
            mac_server = self.arp_table[ip_server]
            p, d = get_path(mymac[eth.src][0], mymac[mac_server][0],
                            mymac[eth.src][1], mymac[mac_server][1])
            print p, d
            if d < minimum:
                minimum = d
                path = p
                selected_server_ip = server

        print "Selected server %s" % selected_server_ip
        print path, minimum

        selected_server_mac = self.arp_table[selected_server_ip]
        selected_server_switch = path[-1][0]
        selected_server_inport = path[-1][1]
        selected_server_outport = path[-1][2]

        reversed_path, d = get_path(selected_server_switch, mymac[eth.src][0],
                                    mymac[selected_server_mac][1], mymac[eth.src][1])

        self.install_path(ev, path[:-1], src_ip, self.virtual_ip)
        self.install_path(ev, reversed_path[1:], self.virtual_ip, src_ip)

        # Setup route to server
        match_ip = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                       ipv4_src=src_ip, ipv4_dst=self.virtual_ip)

        actions_ip = [ofp_parser.OFPActionSetField(eth_dst=selected_server_mac),
                      ofp_parser.OFPActionSetField(
                          ipv4_dst=selected_server_ip),
                      ofp_parser.OFPActionOutput(selected_server_outport)]

        match_arp = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                        arp_spa=src_ip, arp_tpa=self.virtual_ip)

        actions_arp = [ofp_parser.OFPActionSetField(arp_tha=selected_server_mac),
                       ofp_parser.OFPActionSetField(
                           arp_tpa=selected_server_ip),
                       ofp_parser.OFPActionOutput(selected_server_outport)]

        inst_ip = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions_ip)]
        inst_arp = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions_arp)]

        server_dp = self.datapath_list[selected_server_switch]
        mod_ip = ofp_parser.OFPFlowMod(datapath=server_dp, match=match_ip, idle_timeout=10,
                                       instructions=inst_ip, buffer_id=msg.buffer_id)
        mod_arp = ofp_parser.OFPFlowMod(datapath=server_dp, match=match_arp, idle_timeout=10,
                                        instructions=inst_arp, buffer_id=msg.buffer_id)
        server_dp.send_msg(mod_arp)
        server_dp.send_msg(mod_ip)

        # Setup reverse route from server
        match_ip = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                       eth_src=selected_server_mac, eth_dst=eth.src,
                                       ipv4_src=selected_server_ip, ipv4_dst=src_ip)
        match_arp = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                        arp_sha=selected_server_mac, arp_tha=eth.src,
                                        arp_spa=selected_server_ip, arp_tpa=src_ip)

        actions_ip = ([ofp_parser.OFPActionSetField(eth_src=self.virtual_mac),
                       ofp_parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                       ofp_parser.OFPActionOutput(selected_server_inport)])
        actions_arp = ([ofp_parser.OFPActionSetField(arp_sha=self.virtual_mac),
                        ofp_parser.OFPActionSetField(arp_spa=self.virtual_ip),
                        ofp_parser.OFPActionOutput(selected_server_inport)])

        inst_ip = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions_ip)]
        inst_arp = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions_arp)]

        mod_ip = ofp_parser.OFPFlowMod(datapath=server_dp, match=match_ip, idle_timeout=10,
                                       instructions=inst_ip)
        mod_arp = ofp_parser.OFPFlowMod(datapath=server_dp, match=match_arp, idle_timeout=10,
                                        instructions=inst_arp)
        server_dp.send_msg(mod_arp)
        server_dp.send_msg(mod_ip)

        return path[0][2]

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
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
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

        if src not in mymac.keys():
            mymac[src] = (dpid, in_port)
            self.mac_to_port[dpid][src] = in_port

        out_port = ofproto.OFPP_FLOOD

        # packet processing of magic
        # hours of hard work, sweat and tears :')
        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                if dst == self.controller_mac:
                    # servers to controller
                    match_controller = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_ARP,
                        arp_op=arp.ARP_REQUEST,
                        arp_sha=self.controller_mac
                    )
                    self.add_flow(datapath, 2, match_controller, [])
                    return
                elif dst_ip in self.servers:
                    # forbid direct communication with server
                    return
                elif dst in self.mac_to_port[dpid]:
                    # client to client routing
                    out_port = self.mac_to_port[dpid][dst]
                    path, d = get_path(
                        mymac[src][0], mymac[dst][0], mymac[src][1], mymac[dst][1])
                    reverse, d = get_path(
                        mymac[dst][0], mymac[src][0], mymac[dst][1], mymac[src][1])
                    self.install_path(ev, path, src_ip, dst_ip)
                    self.install_path(ev, reverse, dst_ip, src_ip)
                    self.arp_table[src_ip] = src
                    self.arp_table[dst_ip] = dst
            elif dst == mac.BROADCAST_STR and dst_ip in self.arp_table:
                # always try to reply arp requests first
                opcode = arp.ARP_REPLY
                reply_mac = self.arp_table[dst_ip]
                self.send_arp(datapath, src, reply_mac,
                              src_ip, dst_ip, opcode, in_port)
                return
            elif src_ip == self.controller_ip and dst_ip in self.arp_table:
                # install rules to stop arp flood
                match_controller = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_op=arp.ARP_REQUEST,
                    arp_sha=self.controller_mac
                )
                self.add_flow(datapath, 2, match_controller, [])
                return
            elif dst_ip == self.virtual_ip:
                # client to server
                out_port = self.load_balancing_handler(
                    ev, eth, arp_pkt, in_port)
                self.arp_table[src_ip] = src
            elif src_ip in self.servers:
                # server requests mac of client, send arp reply
                opcode = arp.ARP_REPLY
                reply_mac = self.arp_table[dst_ip]
                self.send_arp(datapath, src, reply_mac,
                              src_ip, dst_ip, opcode, in_port)
                return
        elif ipv4_pkt and ipv4_pkt.dst == self.virtual_ip:
            # install load balancing rules when icmp packet arrives
            # still don't know why this is needed
            # should be already installed on arp packet arrival
            out_port = self.load_balancing_handler(ev, eth, ipv4_pkt, in_port)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD and dst != mac.BROADCAST_STR:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 2, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        try:
            for p in ev.msg.body:
                if p.port_no in switch_info[switch.id]:
                    switch_info[switch.id][p.port_no]["bandwidth"] = p.curr_speed
        # Resend request if reply arrives while initializing
        except RuntimeError: 
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def _switch_enter_handler(self, ev):
        switch = ev.switch.dp
        if switch.id not in switches:
            switches.append(switch.id)
            self.datapath_list[switch.id] = switch
            # req = ofp_parser.OFPPortDescStatsRequest(switch)
            # switch.send_msg(req)

        if switches:
            (ifname, agent) = getIfInfo(collector)
            logging.getLogger("requests").setLevel(logging.WARNING)
            logging.getLogger("urllib3").setLevel(logging.WARNING)
            init_sflow(ifname, collector, 10, 10)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        adjacency[s1.dpid][s2.dpid] = s1.port_no
        adjacency[s2.dpid][s1.dpid] = s2.port_no
        # print s1.dpid, s2.dpid
        hub.spawn_after(1, monitor_link, s1, s2)
