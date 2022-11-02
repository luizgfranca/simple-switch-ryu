from ast import parse
from nis import match
from typing import Any, Tuple

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser

from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.controller import Datapath

from ryu.lib.packet import packet as pkt
from ryu.lib.packet import ethernet as eth

class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        self.mac_to_port_table = {}

    def get_ofproto(datapath: Datapath) -> Tuple[ofproto_v1_3, ofproto_v1_3_parser]:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        return (ofproto, parser)

    def get_datapath(self, event) -> Datapath:
        return event.msg.datapath

    def get_table_miss_flow(self, datapath: Datapath) -> Tuple[ofproto_v1_3_parser.OFPMatch, list[ofproto_v1_3_parser.OFPActionOutput]] :
        ofproto, parser = self.get_ofproto()

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]

        return (match, actions)

    def add_flow(self, datapath: Datapath, priority, handler):
        match, actions = handler
        ofproto, parser = self.get_ofproto()

        parser.OFPInstructionActions()

        instruction = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath, 
            priority=priority, 
            match=match, 
            instructions=instruction
        )

        return mod


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        datapath = event.msg.datapath
        self.add_flow(datapath, 0, self.get_table_miss_flow(datapath))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        msg = event.msg
        datapath = self.get_datapath(event)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.mac_to_port_table.setdefault(datapath.id, {})

        packet = pkt.Packet(msg.data)
        ethernet_packet = packet.get_protocol(eth.ethernet)

        destination = ethernet_packet.dst
        source = ethernet_packet.src
        in_port = msg.match['in_port']

        self.logger.info(f'packet_in {datapath.id} {source} {destination} {in_port}')

        self.mac_to_port_table[datapath.id][source] = in_port
        
        if destination in self.mac_to_port_table[datapath.id]:
            out_port = self.mac_to_port_table[datapath.id][destination]
        else: 
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=destination)
            self.add_flow(datapath, 1, match, actions)

        output = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )

        datapath.send_msg(output)

