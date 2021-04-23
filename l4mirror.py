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

class L4Mirror14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4Mirror14, self).__init__(*args, **kwargs)
        self.ht = {}

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
        iph = pkt.get_protocols(ipv4.ipv4)
        tcph = pkt.get_protocols(tcp.tcp)

        out_port = 2 if in_port == 1 else 1
        #########################################################################     
        # if len(pkt.get_protocols(tcp.tcp)):
        #     tcph = pkt.get_protocols(tcp.tcp)[0]
        #     print(tcph.has_flags(tcp.TCP_ACK))
        # initialize variables
        acts = []
        act = None
        srcip, dstip, srcport, dstport = (None, None, None, None)
        iph = None
        tcph = None
        # check whether it is TCP-over-IPv4 or not
        check = False
        # check_10 = False
        # check if it is TCP-over-IPv4
        if (len(pkt.get_protocols(ipv4.ipv4)) and
            len(pkt.get_protocols(tcp.tcp))):

            iph = pkt.get_protocols(ipv4.ipv4)[0]
            # source ip
            srcip = iph.src
            # destination ip
            dstip = iph.dst

            tcph = pkt.get_protocols(tcp.tcp)[0]            
            # source port
            srcport = tcph.src_port
            # destination port
            dstport = tcph.dst_port
            # if a tuple is complete
            if srcip and dstip and srcport and dstport: 
                # set the flow key for the controller
                flow_key = (srcip, dstip, srcport, dstport)  
                act = psr.OFPActionOutput(out_port)    
                acts.append(act)            
                # check = True
                if in_port == 1:
                    check = True                
                elif in_port == 2:
                    if (tcph.has_flags(tcp.TCP_SYN) and 
                        not tcph.has_flags(tcp.TCP_ACK)):  
                        acts.append(psr.OFPActionOutput(3))    
                        # if flow_key not in self.ht:                            
                        self.ht[flow_key] = 1                                                    
                    else:
                        if flow_key in self.ht:                        
                            acts.append(psr.OFPActionOutput(3))
                            self.ht[flow_key] += 1
                            if self.ht[flow_key] == 10:                      
                                del self.ht[flow_key]      
                        elif flow_key not in self.ht:
                            check = True
                        else:
                            return
        else:
            act = psr.OFPActionOutput(out_port)                                  
            acts.append(act)

        print(acts)
        
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
