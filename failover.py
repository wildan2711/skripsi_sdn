# Copyright 2017 Wildan Maulana Syahidillah

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, ipv6, icmp
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import mac, hub
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.ofproto import ether, inet
from thread import start_new_thread
import time
import random

UINT32_MAX = 0xffffffff

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {} # maps dpid to switch object
        self.arp_table = {} # maps IP to MAC
        self.controller_mac = 'dd:dd:dd:dd:dd:dd' # decoy MAC
        self.controller_ip = '10.0.0.100' # decoy IP
        self.server_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3'] # server IPs to monitor
        self.server_switch = 1 # switch dpid with connections to the servers
        self.latency = {} # maps IP to the latency value
        self.virtual_ip = '10.0.0.20'
        self.virtual_mac = 'df:d8:e9:21:34:f2'
        self.server_index = 0
        self.arp_table = {}
        self.rewrite_ip_header = True
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # server discovery
        for server in self.server_ips:
            dst = mac.BROADCAST_STR
            src = self.controller_mac
            dst_ip = server
            src_ip = self.controller_ip
            opcode = arp.ARP_REQUEST
            port = ofproto.OFPP_FLOOD
            self.send_arp(datapath, dst, src, dst_ip, src_ip, opcode, port)

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
    
    def failover_handler(self, ev, src_ip, src_mac, in_port):
        print "setting up failover"        
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        buckets = []

        print "Failover servers: ", self.server_ips
        for server_ip in self.server_ips:
            server_mac = self.arp_table[server_ip]
            outport = self.mac_to_port[datapath.id][server_mac]
            bucket_weight = 0
            bucket_action = [ofp_parser.OFPActionSetField(eth_dst=server_mac),
                             ofp_parser.OFPActionSetField(ipv4_dst=server_ip),
                             ofp_parser.OFPActionOutput(outport)]
            buckets.append(
                ofp_parser.OFPBucket(
                    weight=bucket_weight,
                    watch_port=outport,
                    watch_group=ofp.OFPG_ANY,
                    actions=bucket_action
                )
            )

        group_id = random.randint(0, 2**32)
        req = ofp_parser.OFPGroupMod(
            datapath, ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id,
            buckets
        )
        datapath.send_msg(req)
        group_action = [ofp_parser.OFPActionGroup(group_id)]

        ########### Setup route to server
        match = ofp_parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, 
                                    eth_src=src_mac, eth_dst=self.virtual_mac,
                                    ipv4_src=src_ip, ipv4_dst=self.virtual_ip)

        self.add_flow(datapath, 1, match, group_action)

        ########### Setup reverse route from server
        for server_ip in self.server_ips:
            server_mac = self.arp_table[server_ip]
            outport = self.mac_to_port[datapath.id][server_mac]
            match = ofp_parser.OFPMatch(in_port=outport, eth_type=ether_types.ETH_TYPE_IP, 
                                        eth_src=server_mac, eth_dst=src_mac,
                                        ipv4_src=server_ip, ipv4_dst=src_ip)
            actions = ([ofp_parser.OFPActionSetField(eth_src=self.virtual_mac),
                       ofp_parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                       ofp_parser.OFPActionOutput(in_port)])
            
            self.add_flow(datapath, 1, match, actions)

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

        self.mac_to_port.setdefault(dpid, {})

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
            elif dst == mac.BROADCAST_STR and dst_ip in self.arp_table:
                # always try to reply arp requests first
                opcode = arp.ARP_REPLY
                reply_mac = self.arp_table[dst_ip]
                self.send_arp(datapath, src, reply_mac,
                              src_ip, dst_ip, opcode, in_port)
            elif src_ip == self.controller_ip and dst_ip in self.arp_table:
                # install rules to stop arp flood
                match_controller = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_op=arp.ARP_REQUEST,
                    arp_sha=self.controller_mac
                )
                self.add_flow(datapath, 2, match_controller, [])
            elif dst_ip == self.virtual_ip:
                # client to server
                self.arp_table[src_ip] = src
                opcode = arp.ARP_REPLY
                reply_mac = self.virtual_mac
                self.send_arp(datapath, src, reply_mac,
                              src_ip, dst_ip, opcode, in_port)
                self.failover_handler(ev, src_ip, src, in_port)
            elif src_ip in self.server_ips:
                # server requests mac of client, send arp reply
                opcode = arp.ARP_REPLY
                reply_mac = self.arp_table[dst_ip]
                self.send_arp(datapath, src, reply_mac,
                              src_ip, dst_ip, opcode, in_port)
            return
        elif ipv4_pkt != None:
            src_ip = ipv4_pkt.src
            self.failover_handler(ev, src_ip, src, in_port)

        # print pkt

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        switch = event.switch
        ofp_parser = switch.dp.ofproto_parser
        if switch.dp.id not in self.datapath_list:
            self.datapath_list[switch.dp.id] = switch