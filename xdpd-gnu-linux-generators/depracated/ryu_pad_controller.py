import logging

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2

from ryu.controller import ofp_event#, dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.lib.mac import haddr_to_bin

logger = logging.getLogger(__name__)

class SimpleSwitch12(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch12, self).__init__(*args, **kwargs)        
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        logger.info(ev)
        send_flow_mod(ev.msg.datapath)

def send_flow_mod(datapath):
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser
    
    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = hard_timeout = 0
    priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    
    match = ofp_parser.OFPMatch(in_port=1, eth_dst='ff:ff:ff:ff:ff:ff', pbb_uca=8)
    
    actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]  # ofp_parser.OFPActionExperimenter(experimenter=1)
    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    
    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask, table_id, ofp.OFPFC_ADD, idle_timeout, hard_timeout, priority, 
                                              buffer_id, ofp.OFPP_ANY, ofp.OFPG_ANY, ofp.OFPFF_SEND_FLOW_REM, match, inst)
    datapath.send_msg(req)
    logger.info("flow mod sent")
    
def add_flow(datapath):
    ofproto = datapath.ofproto
    actions = [datapath.ofproto_parser.OFPActionOutput(1)]
    match = datapath.ofproto_parser.OFPMatch(in_port=2, dl_vlan=700)
    mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, 
                                                                 priority=ofproto.OFP_DEFAULT_PRIORITY, flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
    datapath.send_msg(mod)
    logger.info("flow mod added")