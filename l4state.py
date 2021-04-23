from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.ether_types import ETH_TYPE_IP

class L4State14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4State14, self).__init__(*args, **kwargs)
        self.ht = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        ######################################################################### 
          
        # initialize variables
        acts = []
        act = None
        out_port = 1 if in_port == 2 else 2
        srcip, dstip, srcport, dstport = (None, None, None, None)
        # check whether it is TCP-over-IPv4 or not
        check = False
        # check if it is TCP-over-IPv4
        if len(pkt.get_protocols(ipv4.ipv4)) and len(pkt.get_protocols(tcp.tcp)):
            # IPv4 header
            iph = pkt.get_protocols(ipv4.ipv4)[0]
            # check network version
            if iph.version == 4:                         
                # source ip
                srcip = iph.src
                # destination ip
                dstip = iph.dst                
                # TCP header
                tcph = pkt.get_protocols(tcp.tcp)[0]
                # source port
                srcport = tcph.src_port
                # destination port
                dstport = tcph.dst_port
                # if a tuple is complete
                if srcip and dstip and srcport and dstport:
                    check = True
                    # set the flow key for the controller
                    flow_key = (srcip, dstip, srcport, dstport)
                    # if the packet comes from port 1
                    if in_port == 1:
                        # add the flow key if it is not in ht
                        if flow_key not in self.ht:
                            self.ht.add(flow_key)
                    # if the packet comes from port 2
                    if in_port == 2:
                        temp = (dstip, srcip, dstport, srcport)
                        # check the corresponding flow entry
                        # drop the packet if it is not in ht
                        if temp not in self.ht:                            
                            out_port = ofp.OFPPC_NO_FWD                            
                            check = False
        # create actions with out_port
        act = psr.OFPActionOutput(out_port)                       
        acts.append(act)
        # if it is TCP-over-IPv4
        if check:
            # input switch port, network layer protocol, source IP address,
            # destination IP address, transport layer protocol, source port and destination port
            mtc = psr.OFPMatch(in_port=in_port, eth_type=eth.ethertype, ipv4_src=srcip,
                ipv4_dst=dstip, ip_proto=iph.proto, tcp_src=srcport, tcp_dst=dstport)
            self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                return
        #########################################################################

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
