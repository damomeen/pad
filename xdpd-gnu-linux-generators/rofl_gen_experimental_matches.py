from pad_config import ROFL_DIR
from pad_utils import read_template, generate_file, add_fields_properties, approve_fields_with_attribute

OXM_HEADER_BEGIN_END = """
#ifndef %(header)s_MATCHES_H
#define %(header)s_MATCHES_H 1
#include <rofl/common/openflow/coxmatch.h>
namespace rofl
{
%(code)s
}; // end of namespace
#endif
"""
    
OXM_HEADER_SKELETON = """
/** OXM_OF_%(header)s_%(field)s
 *
 */
class coxmatch_ofx_%(header)s_%(field)s :
	public coxmatch
{
public:
	/** constructor
	 */
	coxmatch_ofx_%(header)s_%(field)s(
			uint%(length)s_t %(field)s);
	/**
	 */
	coxmatch_ofx_%(header)s_%(field)s(
			coxmatch const& oxm);
	/** destructor
	 */
	virtual
	~coxmatch_ofx_%(header)s_%(field)s();
	/**
	 */
	uint%(length)s_t
	get_%(header)s_%(field)s() const;
	/**
	 */
	friend std::ostream&
	operator<< (std::ostream& os, coxmatch_ofx_%(header)s_%(field)s const& oxm)
	{
		os << "OXM";
			os << "[" << oxm.get_oxm_class() << ":" << oxm.get_oxm_field() << "]";
			os << "<%(header)s-%(field)s: " << (unsigned int)oxm.u%(length)svalue() << ">";
		return os;
	};
};
"""
OXM_CODE_BEGIN = """
#include <rofl/common/openflow/experimental/matches/%(header)s_matches.h>
using namespace rofl;
"""

OXM_CODE_SKELETON = """
coxmatch_ofx_%(header)s_%(field)s::coxmatch_ofx_%(header)s_%(field)s(
		uint%(length)s_t %(field)s) :
			coxmatch(sizeof(struct ofp_oxm_hdr) + sizeof(uint%(length)s_t))
{
	set_oxm_class(OFPXMC_EXPERIMENTER);
	set_oxm_field(OFPXMT_OFX_%(header_upper)s_%(field_upper)s);
	set_oxm_length(sizeof(uint%(length)s_t));
	oxm_uint%(length)st->%(container)s = %(field)s;
}

coxmatch_ofx_%(header)s_%(field)s::~coxmatch_ofx_%(header)s_%(field)s()
{
}

coxmatch_ofx_%(header)s_%(field)s::coxmatch_ofx_%(header)s_%(field)s(
		coxmatch const& oxm) :
				coxmatch(oxm)
{
	if (OFPXMC_EXPERIMENTER != get_oxm_class())
		throw eOxmInvalClass();
	if (OFPXMT_OFX_%(header_upper)s_%(field_upper)s != get_oxm_field())
		throw eOxmInvalType();
}

uint%(length)s_t
coxmatch_ofx_%(header)s_%(field)s::get_%(header)s_%(field)s() const
{
	return u%(length)svalue();
}
"""

MAKEFILE_AM_SKELETON = """
MAINTAINERCLEANFILES = Makefile.in

noinst_LTLIBRARIES = libopenflow_experimental_matches.la
libopenflow_experimental_matches_la_SOURCES = gtp_matches.h gtp_matches.cc pppoe_matches.h pppoe_matches.cc %(header)s_matches.h %(header)s_matches.cc


library_includedir=$(includedir)/rofl/common/openflow/experimental/matches
library_include_HEADERS = gtp_matches.h pppoe_matches.h %(header)s_matches.h
"""

OPENFLOW_EXPERIMENTAL_SKELETON = """
#ifndef _OPENFLOW_EXPERIMENTAL_H
#define _OPENFLOW_EXPERIMENTAL_H 1

#include "openflow_common.h"

/* OXM Flow match field types for OpenFlow Experimental */ 
enum oxm_ofx_match_fields {

	//OF1.0 backwards compatibility
	OFPXMT_OFX_NW_SRC	= 0,	/* network layer source address */ 
	OFPXMT_OFX_NW_DST	= 1,	/* network layer destination address */
	OFPXMT_OFX_NW_PROTO	= 2,	/* network layer proto/arp code... */
	OFPXMT_OFX_TP_SRC	= 3,	/* transport protocol source port */
	OFPXMT_OFX_TP_DST	= 4,	/* transport protocol destination port */

	/* Reserved (until 20) */

	/* PPP/PPPoE related extensions */
	OFPXMT_OFX_PPPOE_CODE 	= 21,	/* PPPoE code */
	OFPXMT_OFX_PPPOE_TYPE 	= 22,	/* PPPoE type */
	OFPXMT_OFX_PPPOE_SID 	= 23,	/* PPPoE session id */
	OFPXMT_OFX_PPP_PROT 	= 24,	/* PPP protocol */

	/* GTP related extensions */
	OFPXMT_OFX_GTP_MSG_TYPE = 25,	/* GTP message type */
	OFPXMT_OFX_GTP_TEID	= 26,	/* GTP tunnel endpoint identifier */

%s
     /* max value */
    OFPXMT_OFX_MAX,
};
#endif /* _OPENFLOW_EXPERIMENTAL_H */
"""

OPENFLOW_PIPELINE_MATCH_IDS_SKELETON = """
typedef enum{
	/* phy */
	OF1X_MATCH_IN_PORT,		/* Switch input port. */		//required
	OF1X_MATCH_IN_PHY_PORT,		/* Switch physical input port. */
	
	/* metadata */
	OF1X_MATCH_METADATA,		/* Metadata passed between tables. */

	/* eth */
	OF1X_MATCH_ETH_DST,		/* Ethernet destination address. */	//required
	OF1X_MATCH_ETH_SRC,		/* Ethernet source address. */		//required
	OF1X_MATCH_ETH_TYPE,		/* Ethernet frame type. */		//required
	OF1X_MATCH_VLAN_VID,		/* VLAN id. */
	OF1X_MATCH_VLAN_PCP,		/* VLAN priority. */

	/* mpls */
	OF1X_MATCH_MPLS_LABEL,		/* MPLS label. */
	OF1X_MATCH_MPLS_TC,		/* MPLS TC. */
	OF1X_MATCH_MPLS_BOS,		/* MPLS BoS flag. */

	/* arp */
	OF1X_MATCH_ARP_OP,		/* ARP opcode. */
	OF1X_MATCH_ARP_SPA,		/* ARP source IPv4 address. */
	OF1X_MATCH_ARP_TPA,		/* ARP target IPv4 address. */
	OF1X_MATCH_ARP_SHA,		/* ARP source hardware address. */
	OF1X_MATCH_ARP_THA,		/* ARP target hardware address. */

	/* network layer */
	OF1X_MATCH_NW_PROTO,		/* Network layer Ip proto/arp code. OF10 ONLY */	//required
	OF1X_MATCH_NW_SRC,		/* Network layer source address. OF10 ONLY */		//required
	OF1X_MATCH_NW_DST,		/* Network layer destination address. OF10 ONLY */	//required
	
	/* ipv4 */
	OF1X_MATCH_IP_DSCP,		/* IP DSCP (6 bits in ToS field). */
	OF1X_MATCH_IP_ECN,		/* IP ECN (2 bits in ToS field). */
	OF1X_MATCH_IP_PROTO,		/* IP protocol. */			//required
	OF1X_MATCH_IPV4_SRC,		/* IPv4 source address. */		//required
	OF1X_MATCH_IPV4_DST,		/* IPv4 destination address. */		//required

	/* ipv6 */
	OF1X_MATCH_IPV6_SRC,		/* IPv6 source address. */		//required
	OF1X_MATCH_IPV6_DST,		/* IPv6 destination address. */		//required
	OF1X_MATCH_IPV6_FLABEL,		/* IPv6 Flow Label */
	OF1X_MATCH_ICMPV6_TYPE,		/* ICMPv6 type. */
	OF1X_MATCH_ICMPV6_CODE,		/* ICMPv6 code. */
	OF1X_MATCH_IPV6_ND_TARGET,	/* Target address for ND. */
	OF1X_MATCH_IPV6_ND_SLL,		/* Source link-layer for ND. */
	OF1X_MATCH_IPV6_ND_TLL,		/* Target link-layer for ND. */
	OF1X_MATCH_IPV6_EXTHDR,		/* Extension header */

	/* transport */
	OF1X_MATCH_TP_SRC,		/* TCP/UDP source port. OF10 ONLY */	//required
	OF1X_MATCH_TP_DST,		/* TCP/UDP dest port. OF10 ONLY */	//required
	OF1X_MATCH_TCP_SRC,		/* TCP source port. */			//required
	OF1X_MATCH_TCP_DST,		/* TCP destination port. */		//required
	OF1X_MATCH_UDP_SRC,	        /* UDP source port. */			//required
	OF1X_MATCH_UDP_DST,		/* UDP destination port. */		//required
	OF1X_MATCH_SCTP_SRC,		/* SCTP source port. */
	OF1X_MATCH_SCTP_DST,		/* SCTP destination port. */
	OF1X_MATCH_ICMPV4_TYPE,		/* ICMP type. */
	OF1X_MATCH_ICMPV4_CODE,		/* ICMP code. */

	/* other */
	OF1X_MATCH_PBB_ISID,
	OF1X_MATCH_TUNNEL_ID,

	/********************************/
	/**** Extensions out of spec ****/
	/********************************/

	/* PPP/PPPoE related extensions */
	OF1X_MATCH_PPPOE_CODE,		/* PPPoE code */
	OF1X_MATCH_PPPOE_TYPE,		/* PPPoE type */
	OF1X_MATCH_PPPOE_SID,		/* PPPoE session id */
	OF1X_MATCH_PPP_PROT,		/* PPP protocol */
	
	/* GTP related extensions */
	OF1X_MATCH_GTP_MSG_TYPE,	/* GTP message type */
	OF1X_MATCH_GTP_TEID,		/* GTP teid */
    
%s
	/* max value */
	OF1X_MATCH_MAX,
}of1x_match_type_t;

"""

ROFL_PIPELINE_MATCH_AUTOGENERATED_H_SKELOTON = """
#ifndef __OF1X_MATCH_AUTOGENERATED_H__
#define __OF1X_MATCH_AUTOGENERATED_H__

#include <inttypes.h>
#include "rofl.h"
#include "../../../common/ternary_fields.h"
#include "of1x_packet_matches.h"
#include "of1x_utils.h"

#define OF1X_VLAN_PRESENT_MASK 0x1000
#define OF1X_VLAN_ID_MASK 0x0FFF

%s
typedef struct of1x_match{
	
	//Type
	of1x_match_type_t type;

	//Ternary value
	utern_t* value;
	
	//Previous entry
	struct of1x_match* prev;
	
	//Next entry
	struct of1x_match* next;
	
	/* Fast validation flags */
	//Bitmap of required OF versions
	of1x_ver_req_t ver_req; 
	
	//OF1.0 only
	bool has_wildcard;
}of1x_match_t;

//C++ extern C 
ROFL_BEGIN_DECLS

%s
of1x_match_t* __of1x_copy_match(of1x_match_t* match);
bool __of1x_check_match(const of1x_packet_matches_t* pkt, of1x_match_t* it);
void __of1x_dump_matches(of1x_match_t* matches);

//C++ extern C
ROFL_END_DECLS

#endif //__OF1X_MATCH_AUTOGENERATED_H__
"""

ROFL_PIPELINE_MATCH_INIT_SKELETON = """
//PPPoE
inline of1x_match_t* of1x_init_%(header)s_%(field)s_match(of1x_match_t* prev, of1x_match_t* next, uint%(length)s_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_%(header_upper)s_%(field_upper)s; 
	match->value = __init_utern%(length)s(value, OF1X_%(masking)s_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2 (extensions)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
"""

ROFL_PIPELINE_MATCH_COPY_SKELETON = """
/*
* Copy match to heap. Leaves next and prev pointers to NULL
*/
inline of1x_match_t* __of1x_copy_match(of1x_match_t* match){
	switch(match->type){

		case OF1X_MATCH_IN_PORT: return of1x_init_port_in_match(NULL, NULL, match->value->value.u32);
		case OF1X_MATCH_IN_PHY_PORT: return of1x_init_port_in_phy_match(NULL, NULL, match->value->value.u32);

	  	case OF1X_MATCH_METADATA: return of1x_init_metadata_match(NULL,NULL,match->value->value.u64,match->value->mask.u64);	
   
		case OF1X_MATCH_ETH_DST:  return of1x_init_eth_dst_match(NULL,NULL,match->value->value.u64,match->value->mask.u64); 
   		case OF1X_MATCH_ETH_SRC:  return  of1x_init_eth_src_match(NULL,NULL,match->value->value.u64,match->value->mask.u64);
   		case OF1X_MATCH_ETH_TYPE: return of1x_init_eth_type_match(NULL,NULL,match->value->value.u16);

   		case OF1X_MATCH_VLAN_VID: return of1x_init_vlan_vid_match(NULL,NULL,match->value->value.u16,match->value->mask.u16); 
   		case OF1X_MATCH_VLAN_PCP: return of1x_init_vlan_pcp_match(NULL,NULL,match->value->value.u8); 

   		case OF1X_MATCH_MPLS_LABEL: return of1x_init_mpls_label_match(NULL,NULL,match->value->value.u32); 
   		case OF1X_MATCH_MPLS_TC: return of1x_init_mpls_tc_match(NULL,NULL,match->value->value.u8); 
   		case OF1X_MATCH_MPLS_BOS: return of1x_init_mpls_bos_match(NULL,NULL,match->value->value.u8); 

   		case OF1X_MATCH_ARP_OP: return of1x_init_arp_opcode_match(NULL,NULL,match->value->value.u16);
   		case OF1X_MATCH_ARP_SHA: return of1x_init_arp_sha_match(NULL,NULL,match->value->value.u64,match->value->mask.u64);
   		case OF1X_MATCH_ARP_SPA: return of1x_init_arp_spa_match(NULL,NULL,match->value->value.u32,match->value->mask.u32);
   		case OF1X_MATCH_ARP_THA: return of1x_init_arp_tha_match(NULL,NULL,match->value->value.u64,match->value->mask.u64);
   		case OF1X_MATCH_ARP_TPA: return of1x_init_arp_tpa_match(NULL,NULL,match->value->value.u32,match->value->mask.u32);

		case OF1X_MATCH_NW_PROTO: return of1x_init_nw_proto_match(NULL,NULL,match->value->value.u8); 
   		case OF1X_MATCH_NW_SRC: return of1x_init_nw_src_match(NULL,NULL,match->value->value.u32,match->value->mask.u32); 
   		case OF1X_MATCH_NW_DST: return of1x_init_nw_dst_match(NULL,NULL,match->value->value.u32,match->value->mask.u32); 

		case OF1X_MATCH_IP_PROTO: return of1x_init_ip_proto_match(NULL,NULL,match->value->value.u8); 
   		case OF1X_MATCH_IP_ECN: return of1x_init_ip_ecn_match(NULL,NULL,match->value->value.u8); 
   		case OF1X_MATCH_IP_DSCP: return of1x_init_ip_dscp_match(NULL,NULL,match->value->value.u8);

   		case OF1X_MATCH_IPV4_SRC: return of1x_init_ip4_src_match(NULL,NULL,match->value->value.u32,match->value->mask.u32); 
   		case OF1X_MATCH_IPV4_DST: return of1x_init_ip4_dst_match(NULL,NULL,match->value->value.u32,match->value->mask.u32); 

   		case OF1X_MATCH_TCP_SRC: return of1x_init_tcp_src_match(NULL,NULL,match->value->value.u16); 
   		case OF1X_MATCH_TCP_DST: return of1x_init_tcp_dst_match(NULL,NULL,match->value->value.u16); 

   		case OF1X_MATCH_UDP_SRC: return of1x_init_udp_src_match(NULL,NULL,match->value->value.u16); 
   		case OF1X_MATCH_UDP_DST: return of1x_init_udp_dst_match(NULL,NULL,match->value->value.u16); 

   		case OF1X_MATCH_SCTP_SRC: return of1x_init_sctp_src_match(NULL,NULL,match->value->value.u16); 
   		case OF1X_MATCH_SCTP_DST: return of1x_init_sctp_dst_match(NULL,NULL,match->value->value.u16); 

		case OF1X_MATCH_TP_SRC: return of1x_init_tp_src_match(NULL,NULL,match->value->value.u16); 
   		case OF1X_MATCH_TP_DST: return of1x_init_tp_dst_match(NULL,NULL,match->value->value.u16); 


		case OF1X_MATCH_ICMPV4_TYPE: return of1x_init_icmpv4_type_match(NULL,NULL,match->value->value.u8); 
   		case OF1X_MATCH_ICMPV4_CODE: return of1x_init_icmpv4_code_match(NULL,NULL,match->value->value.u8); 
  		
		case OF1X_MATCH_IPV6_SRC: return of1x_init_ip6_src_match(NULL,NULL,match->value->value.u128, match->value->mask.u128);
		case OF1X_MATCH_IPV6_DST: return of1x_init_ip6_dst_match(NULL,NULL,match->value->value.u128, match->value->mask.u128);
		case OF1X_MATCH_IPV6_FLABEL: return of1x_init_ip6_flabel_match(NULL,NULL,match->value->value.u64);
		case OF1X_MATCH_IPV6_ND_TARGET: return of1x_init_ip6_nd_target_match(NULL,NULL,match->value->value.u128);
		case OF1X_MATCH_IPV6_ND_SLL: return of1x_init_ip6_nd_sll_match(NULL,NULL,match->value->value.u64);
		case OF1X_MATCH_IPV6_ND_TLL: return of1x_init_ip6_nd_tll_match(NULL,NULL,match->value->value.u64);
		case OF1X_MATCH_IPV6_EXTHDR: return of1x_init_ip6_exthdr_match(NULL,NULL,match->value->value.u64, match->value->mask.u64);
		
		case OF1X_MATCH_ICMPV6_TYPE: return of1x_init_icmpv6_type_match(NULL,NULL,match->value->value.u64);
		case OF1X_MATCH_ICMPV6_CODE: return of1x_init_icmpv6_code_match(NULL,NULL,match->value->value.u64);
		
		/* PPP/PPPoE related extensions */
   		case OF1X_MATCH_PPPOE_CODE: return of1x_init_pppoe_code_match(NULL,NULL,match->value->value.u8); 
   		case OF1X_MATCH_PPPOE_TYPE: return of1x_init_pppoe_type_match(NULL,NULL,match->value->value.u8); 
   		case OF1X_MATCH_PPPOE_SID: return of1x_init_pppoe_session_match(NULL,NULL,match->value->value.u16); 
   		case OF1X_MATCH_PPP_PROT: return of1x_init_ppp_prot_match(NULL,NULL,match->value->value.u16); 

		//PBB   		
		case OF1X_MATCH_PBB_ISID: return of1x_init_pbb_isid_match(NULL,NULL,match->value->value.u32, match->value->mask.u32); 
		//Tunnel ID
		case OF1X_MATCH_TUNNEL_ID: return of1x_init_tunnel_id_match(NULL,NULL,match->value->value.u64, match->value->mask.u64); 

   		/* GTP related extensions */
   		case OF1X_MATCH_GTP_MSG_TYPE: return of1x_init_gtp_msg_type_match(NULL,NULL,match->value->value.u8);
   		case OF1X_MATCH_GTP_TEID: return of1x_init_gtp_teid_match(NULL,NULL,match->value->value.u32,match->value->mask.u32);

%s
		case OF1X_MATCH_MAX:
				break;
	}	
	assert(0);	
	return NULL;
}
"""

ROFL_PIPELINE_MATCH_CHECK_SKELETON="""
/*
* Check fields against packet
*/
inline bool __of1x_check_match(const of1x_packet_matches_t* pkt, of1x_match_t* it){
	if(!it)
		return false;
	
	switch(it->type){
		//Phy
		case OF1X_MATCH_IN_PORT: return __utern_compare32(it->value,pkt->port_in);
		case OF1X_MATCH_IN_PHY_PORT: if(!pkt->port_in) return false; //According to spec
					return __utern_compare32(it->value,pkt->phy_port_in);
		//Metadata
	  	case OF1X_MATCH_METADATA: return __utern_compare64(it->value,pkt->metadata); 
		
		//802
   		case OF1X_MATCH_ETH_DST:  return __utern_compare64(it->value,pkt->eth_dst);
   		case OF1X_MATCH_ETH_SRC:  return __utern_compare64(it->value,pkt->eth_src);
   		case OF1X_MATCH_ETH_TYPE: return __utern_compare16(it->value,pkt->eth_type);
		
		//802.1q
   		case OF1X_MATCH_VLAN_VID: 
					if( (it->value->value.u16&OF1X_VLAN_PRESENT_MASK) && (!pkt->has_vlan) )
						return false;
					if( (!(it->value->value.u16&OF1X_VLAN_PRESENT_MASK)) && (pkt->has_vlan) )
						return false;
					return __utern_compare16(it->value,pkt->vlan_vid);
   		case OF1X_MATCH_VLAN_PCP: if(!pkt->has_vlan) return false;
					return __utern_compare8(it->value,pkt->vlan_pcp);

		//MPLS
   		case OF1X_MATCH_MPLS_LABEL: if(!(pkt->eth_type == OF1X_ETH_TYPE_MPLS_UNICAST || pkt->eth_type == OF1X_ETH_TYPE_MPLS_MULTICAST )) return false;
					return __utern_compare32(it->value,pkt->mpls_label);
   		case OF1X_MATCH_MPLS_TC: if(!(pkt->eth_type == OF1X_ETH_TYPE_MPLS_UNICAST || pkt->eth_type == OF1X_ETH_TYPE_MPLS_MULTICAST )) return false; 
					return __utern_compare8(it->value,pkt->mpls_tc);
   		case OF1X_MATCH_MPLS_BOS: if(!(pkt->eth_type == OF1X_ETH_TYPE_MPLS_UNICAST || pkt->eth_type == OF1X_ETH_TYPE_MPLS_MULTICAST )) return false; 
					return __utern_compare8(it->value,pkt->mpls_bos);
	
		//ARP
   		case OF1X_MATCH_ARP_OP: if(!(pkt->eth_type == OF1X_ETH_TYPE_ARP)) return false;
   					return __utern_compare16(it->value,pkt->arp_opcode);
   		case OF1X_MATCH_ARP_SHA: if(!(pkt->eth_type == OF1X_ETH_TYPE_ARP)) return false;
   					return __utern_compare64(it->value,pkt->arp_sha);
   		case OF1X_MATCH_ARP_SPA: if(!(pkt->eth_type == OF1X_ETH_TYPE_ARP)) return false;
					return __utern_compare32(it->value, pkt->arp_spa);
   		case OF1X_MATCH_ARP_THA: if(!(pkt->eth_type == OF1X_ETH_TYPE_ARP)) return false;
   					return __utern_compare64(it->value,pkt->arp_tha);
   		case OF1X_MATCH_ARP_TPA: if(!(pkt->eth_type == OF1X_ETH_TYPE_ARP)) return false;
					return __utern_compare32(it->value, pkt->arp_tpa);

		//NW (OF1.0 only)
   		case OF1X_MATCH_NW_PROTO: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV4 || pkt->eth_type == OF1X_ETH_TYPE_IPV6 || pkt->eth_type == OF1X_ETH_TYPE_ARP || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && (pkt->ppp_proto == OF1X_PPP_PROTO_IP4 || pkt->ppp_proto == OF1X_PPP_PROTO_IP6) ))) return false;
					if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
						return __utern_compare8(it->value,pkt->arp_opcode);
					else 
						return __utern_compare8(it->value,pkt->ip_proto);
	
   		case OF1X_MATCH_NW_SRC:	if((pkt->eth_type == OF1X_ETH_TYPE_IPV4 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP4 ))) 
						return __utern_compare32(it->value, pkt->ipv4_src); 
					if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
						return __utern_compare32(it->value, pkt->arp_spa); 
					return false;
   		case OF1X_MATCH_NW_DST:	if((pkt->eth_type == OF1X_ETH_TYPE_IPV4 ||(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP4 )))  
						return __utern_compare32(it->value, pkt->ipv4_dst);
					if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
						return __utern_compare32(it->value, pkt->arp_tpa); 
					return false;
		//IP
   		case OF1X_MATCH_IP_PROTO: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV4 || pkt->eth_type == OF1X_ETH_TYPE_IPV6 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && (pkt->ppp_proto == OF1X_PPP_PROTO_IP4 || pkt->ppp_proto == OF1X_PPP_PROTO_IP6) ))) return false; 
					return __utern_compare8(it->value,pkt->ip_proto);
		case OF1X_MATCH_IP_ECN: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV4 || pkt->eth_type == OF1X_ETH_TYPE_IPV6 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP4 ))) return false; //NOTE OF1X_PPP_PROTO_IP6
					return __utern_compare8(it->value,pkt->ip_ecn);
	
		case OF1X_MATCH_IP_DSCP: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV4 || pkt->eth_type == OF1X_ETH_TYPE_IPV6 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP4 ))) return false; //NOTE OF1X_PPP_PROTO_IP6
					return __utern_compare8(it->value,pkt->ip_dscp);
		
		//IPv4
   		case OF1X_MATCH_IPV4_SRC: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV4 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP4 ))) return false; 
					return __utern_compare32(it->value, pkt->ipv4_src);
   		case OF1X_MATCH_IPV4_DST:if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV4 ||(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP4 ))) return false;  
					return __utern_compare32(it->value, pkt->ipv4_dst);
	
		//TCP
   		case OF1X_MATCH_TCP_SRC: if(!(pkt->ip_proto == OF1X_IP_PROTO_TCP)) return false; 
					return __utern_compare16(it->value,pkt->tcp_src);
   		case OF1X_MATCH_TCP_DST: if(!(pkt->ip_proto == OF1X_IP_PROTO_TCP)) return false; 
					return __utern_compare16(it->value,pkt->tcp_dst);
	
		//UDP
   		case OF1X_MATCH_UDP_SRC: if(!(pkt->ip_proto == OF1X_IP_PROTO_UDP)) return false; 	
					return __utern_compare16(it->value,pkt->udp_src);
   		case OF1X_MATCH_UDP_DST: if(!(pkt->ip_proto == OF1X_IP_PROTO_UDP)) return false; 
					return __utern_compare16(it->value,pkt->udp_dst);
		//SCTP
   		case OF1X_MATCH_SCTP_SRC: if(!(pkt->ip_proto == OF1X_IP_PROTO_SCTP)) return false; 
					return __utern_compare16(it->value,pkt->tcp_src);
   		case OF1X_MATCH_SCTP_DST: if(!(pkt->ip_proto == OF1X_IP_PROTO_SCTP)) return false; 
					return __utern_compare16(it->value,pkt->tcp_dst);
	
		//TP (OF1.0 only)
   		case OF1X_MATCH_TP_SRC: if((pkt->ip_proto == OF1X_IP_PROTO_TCP))
						return __utern_compare16(it->value,pkt->tcp_src);
   					if((pkt->ip_proto == OF1X_IP_PROTO_UDP))
						return __utern_compare16(it->value,pkt->udp_src);
					if((pkt->ip_proto == OF1X_IP_PROTO_ICMPV4))
						return __utern_compare16(it->value,pkt->icmpv4_type);
					return false;

   		case OF1X_MATCH_TP_DST: if((pkt->ip_proto == OF1X_IP_PROTO_TCP))
						return __utern_compare16(it->value,pkt->tcp_dst);
   					if((pkt->ip_proto == OF1X_IP_PROTO_UDP))
						return __utern_compare16(it->value,pkt->udp_dst);
					if((pkt->ip_proto == OF1X_IP_PROTO_ICMPV4))
						return __utern_compare16(it->value,pkt->icmpv4_code);
					return false;
		
		//ICMPv4
		case OF1X_MATCH_ICMPV4_TYPE: if(!(pkt->ip_proto == OF1X_IP_PROTO_ICMPV4)) return false; 
					return __utern_compare8(it->value,pkt->icmpv4_type);
   		case OF1X_MATCH_ICMPV4_CODE: if(!(pkt->ip_proto == OF1X_IP_PROTO_ICMPV4)) return false; 
					return __utern_compare8(it->value,pkt->icmpv4_code);
  		
		//IPv6
		case OF1X_MATCH_IPV6_SRC: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV6 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP6 ))) return false; 
					return __utern_compare128(it->value, pkt->ipv6_src);
		case OF1X_MATCH_IPV6_DST: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV6 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP6 ))) return false; 
					return __utern_compare128(it->value, pkt->ipv6_dst);
		case OF1X_MATCH_IPV6_FLABEL: if(!(pkt->eth_type == OF1X_ETH_TYPE_IPV6 || (pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION && pkt->ppp_proto == OF1X_PPP_PROTO_IP6 ))) return false; 
					return __utern_compare64(it->value, pkt->ipv6_flabel);
		case OF1X_MATCH_IPV6_ND_TARGET: if(!(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6)) return false; 
					return __utern_compare128(it->value,pkt->ipv6_nd_target);
		case OF1X_MATCH_IPV6_ND_SLL: if(!(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6 && pkt->ipv6_nd_sll)) return false; //NOTE OPTION SLL active
					return __utern_compare64(it->value, pkt->ipv6_nd_sll);
		case OF1X_MATCH_IPV6_ND_TLL: if(!(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6 && pkt->ipv6_nd_tll)) return false; //NOTE OPTION TLL active
					return __utern_compare64(it->value, pkt->ipv6_nd_tll);
		case OF1X_MATCH_IPV6_EXTHDR: //TODO not yet implemented.
			return false;
			break;
					
		//ICMPv6
		case OF1X_MATCH_ICMPV6_TYPE: if(!(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6)) return false; 
					return __utern_compare64(it->value, pkt->icmpv6_type);
		case OF1X_MATCH_ICMPV6_CODE: if(!(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6 )) return false; 
					return __utern_compare64(it->value, pkt->icmpv6_code);
			
		//PPPoE related extensions
   		case OF1X_MATCH_PPPOE_CODE: if(!(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_DISCOVERY || pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION )) return false;  
						return __utern_compare8(it->value,pkt->pppoe_code);
   		case OF1X_MATCH_PPPOE_TYPE: if(!(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_DISCOVERY || pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION )) return false; 
						return __utern_compare8(it->value,pkt->pppoe_type);
   		case OF1X_MATCH_PPPOE_SID: if(!(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_DISCOVERY || pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION )) return false; 
						return __utern_compare16(it->value,pkt->pppoe_sid);

		//PPP 
   		case OF1X_MATCH_PPP_PROT: if(!(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION )) return false; 
						return __utern_compare16(it->value,pkt->ppp_proto);
	
		//PBB
   		case OF1X_MATCH_PBB_ISID: if(pkt->eth_type == OF1X_ETH_TYPE_PBB) return false;	
						return __utern_compare32(it->value,pkt->pbb_isid);
	 	//TUNNEL id
   		case OF1X_MATCH_TUNNEL_ID: return __utern_compare64(it->value,pkt->tunnel_id);
 
		//GTP
   		case OF1X_MATCH_GTP_MSG_TYPE: if (!(pkt->ip_proto == OF1X_IP_PROTO_UDP || pkt->udp_dst == OF1X_UDP_DST_PORT_GTPU)) return false;
   						return __utern_compare8(it->value,pkt->gtp_msg_type);
   		case OF1X_MATCH_GTP_TEID: if (!(pkt->ip_proto == OF1X_IP_PROTO_UDP || pkt->udp_dst == OF1X_UDP_DST_PORT_GTPU)) return false;
   						return __utern_compare32(it->value,pkt->gtp_teid);
                        
%s
		case OF1X_MATCH_MAX:
				break;
	}
	assert(0);	
	return NULL;
}
"""


ROFL_PIPELINE_MATCH_DUMP_SKELETON = """
//Matches with mask (including matches that do not support)
void __of1x_dump_matches(of1x_match_t* matches){
	of1x_match_t* it;
	for(it=matches;it;it=it->next){
		switch(it->type){
			case OF1X_MATCH_IN_PORT: ROFL_PIPELINE_DEBUG_NO_PREFIX("[PORT_IN:%%u], ",it->value->value.u32); 
				break;
			case OF1X_MATCH_IN_PHY_PORT: ROFL_PIPELINE_DEBUG_NO_PREFIX("[PHY_PORT_IN:%%u], ",it->value->value.u32);
				break; 

			case OF1X_MATCH_METADATA: ROFL_PIPELINE_DEBUG_NO_PREFIX("[METADATA:0x%%llx|0x%%llx],  ",(long long unsigned)it->value->value.u64,(long long unsigned)it->value->mask.u64); 
				break;

			case OF1X_MATCH_ETH_DST: ROFL_PIPELINE_DEBUG_NO_PREFIX("[ETH_DST:0x%%llx|0x%%llx],  ",(long long unsigned)it->value->value.u64,(long long unsigned)it->value->mask.u64);
				break; 
			case OF1X_MATCH_ETH_SRC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[ETH_SRC:0x%%llx|0x%%llx], ",(long long unsigned)it->value->value.u64,(long long unsigned)it->value->mask.u64);
				break; 
			case OF1X_MATCH_ETH_TYPE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[ETH_TYPE:0x%%x], ",it->value->value.u16);
				break; 

			case OF1X_MATCH_VLAN_VID:  	if(!(it->value->value.u16&OF1X_VLAN_PRESENT_MASK))
								ROFL_PIPELINE_DEBUG_NO_PREFIX("[NO_VLAN], ");
							else
								ROFL_PIPELINE_DEBUG_NO_PREFIX("[VLAN_ID:%%u|0x%%x], ",it->value->value.u16&OF1X_VLAN_ID_MASK,it->value->mask.u16);
				break; 
			case OF1X_MATCH_VLAN_PCP:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[VLAN_PCP:%%u], ",it->value->value.u8);
				break; 

			case OF1X_MATCH_MPLS_LABEL:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[MPLS_LABEL:0x%%x], ",it->value->value.u32);
				break; 
			case OF1X_MATCH_MPLS_TC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[MPLS_TC:0x%%x], ",it->value->value.u8);
				break; 
			case OF1X_MATCH_MPLS_BOS:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[MPLS_BOS:0x%%x], ",it->value->value.u8);
				break;

			case OF1X_MATCH_ARP_OP: ROFL_PIPELINE_DEBUG_NO_PREFIX("[ARP_OPCODE:0x%%x], ",it->value->value.u16);
				break;
			case OF1X_MATCH_ARP_SHA: ROFL_PIPELINE_DEBUG_NO_PREFIX("[ARP_SHA:0x%%llx|0x%%llx], ",(long long unsigned)it->value->value.u64,(long long unsigned)it->value->mask.u64);
				break;
			case OF1X_MATCH_ARP_SPA: ROFL_PIPELINE_DEBUG_NO_PREFIX("[ARP_SPA:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break;
			case OF1X_MATCH_ARP_THA: ROFL_PIPELINE_DEBUG_NO_PREFIX("[ARP_THA:0x%%llx|0x%%llx], ",(long long unsigned)it->value->value.u64,(long long unsigned)it->value->mask.u64);
				break;
			case OF1X_MATCH_ARP_TPA: ROFL_PIPELINE_DEBUG_NO_PREFIX("[ARP_TPA:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break;

			case OF1X_MATCH_NW_PROTO:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[NW_PROTO:%%u|0x%%x], ",it->value->value.u8,it->value->mask.u8);
				break; 
			case OF1X_MATCH_NW_SRC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[NW_SRC:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break; 
			case OF1X_MATCH_NW_DST:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[NW_DST:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break; 

			case OF1X_MATCH_IP_ECN:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IP_ECN:0x%%x], ",it->value->value.u8);
				break; 
			case OF1X_MATCH_IP_DSCP:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IP_DSCP:0x%%x], ",it->value->value.u8);
				break; 
			case OF1X_MATCH_IP_PROTO:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IP_PROTO:%%u|0x%%x], ",it->value->value.u8,it->value->mask.u8);
				break; 

			case OF1X_MATCH_IPV4_SRC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IP4_SRC:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break; 
			case OF1X_MATCH_IPV4_DST:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IP4_DST:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break; 

			case OF1X_MATCH_TCP_SRC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[TCP_SRC:%%u], ",it->value->value.u16);
				break; 
			case OF1X_MATCH_TCP_DST:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[TCP_DST:%%u], ",it->value->value.u16);
				break; 

			case OF1X_MATCH_UDP_SRC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[UDP_SRC:%%u], ",it->value->value.u16);
				break; 
			case OF1X_MATCH_UDP_DST:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[UDP_DST:%%u], ",it->value->value.u16);
				break; 

			case OF1X_MATCH_SCTP_SRC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[SCTP_SRC:%%u], ",it->value->value.u16);
				break; 
			case OF1X_MATCH_SCTP_DST:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[SCTP_DST:%%u], ",it->value->value.u16);
				break; 

			//OF1.0 only
			case OF1X_MATCH_TP_SRC:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[TP_SRC:%%u], ",it->value->value.u16);
				break; 
			case OF1X_MATCH_TP_DST:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[TP_DST:%%u], ",it->value->value.u16);
				break; 


			case OF1X_MATCH_ICMPV4_TYPE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[ICMPV4_TYPE:%%u], ",it->value->value.u8);
				break; 
			case OF1X_MATCH_ICMPV4_CODE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[ICMPV4_CODE:%%u], ",it->value->value.u8);
				break; 
			
			//IPv6
			case OF1X_MATCH_IPV6_SRC: ROFL_PIPELINE_DEBUG_NO_PREFIX("[IPV6_SRC:0x%%lx:%%lx|0x%%lx:%%lx], ",UINT128__T_HI(it->value->value.u128),UINT128__T_LO(it->value->value.u128),UINT128__T_HI(it->value->mask.u128),UINT128__T_LO(it->value->mask.u128));
				break;
			case OF1X_MATCH_IPV6_DST: ROFL_PIPELINE_DEBUG_NO_PREFIX("[IPV6_DST:0x%%lx:%%lx|0x%%lx:%%lx], ",UINT128__T_HI(it->value->value.u128),UINT128__T_LO(it->value->value.u128),UINT128__T_HI(it->value->mask.u128),UINT128__T_LO(it->value->mask.u128));
				break;
			case OF1X_MATCH_IPV6_FLABEL:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IPV6_FLABEL:%%lu], ",it->value->value.u64);
				break; 
			case OF1X_MATCH_IPV6_ND_TARGET: ROFL_PIPELINE_DEBUG_NO_PREFIX("[IPV6_ND_TARGET:0x%%lx:%%lx], ",UINT128__T_HI(it->value->value.u128),UINT128__T_LO(it->value->value.u128));
				break;
			case OF1X_MATCH_IPV6_ND_SLL:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IPV6_ND_SLL:%%lu], ",it->value->value.u64);
				break; 
			case OF1X_MATCH_IPV6_ND_TLL:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IPV6_ND_TLL:%%lu], ",it->value->value.u64);
				break; 
			case OF1X_MATCH_IPV6_EXTHDR:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[IPV6_EXTHDR:%%lu|0x%%lx], ",it->value->value.u16,it->value->mask.u16);
				break; 
			//ICMPv6
			case OF1X_MATCH_ICMPV6_TYPE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[ICMPV6_TYPE:%%lu], ",it->value->value.u8);
				break; 
			case OF1X_MATCH_ICMPV6_CODE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[ICMPV6_CODE:%%lu], ",it->value->value.u8);
				break; 
					
			//PBB	
			case OF1X_MATCH_PBB_ISID: ROFL_PIPELINE_DEBUG_NO_PREFIX("[PBB_ISID:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break;
			//TUNNEL ID
			case OF1X_MATCH_TUNNEL_ID: ROFL_PIPELINE_DEBUG_NO_PREFIX("[TUNNEL_ID:0x%%llx|0x%%llx], ",(long long unsigned)it->value->value.u64,(long long unsigned)it->value->mask.u64);
				break;

			/* PPP/PPPoE related extensions */
			case OF1X_MATCH_PPPOE_CODE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[PPPOE_CODE:%%u], ",it->value->value.u8);
				break; 
			case OF1X_MATCH_PPPOE_TYPE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[PPPOE_TYPE:%%u], ",it->value->value.u8);
				break; 
			case OF1X_MATCH_PPPOE_SID:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[PPPOE_SID:%%u], ",it->value->value.u16);
				break; 

			case OF1X_MATCH_PPP_PROT:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[PPP_PROT:%%u] ",it->value->value.u16);
				break; 

			/* GTP related extensions */
			case OF1X_MATCH_GTP_MSG_TYPE:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[GTP_MSG_TYPE:%%u], ",it->value->value.u8);
				break;
			case OF1X_MATCH_GTP_TEID:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[GTP_TEID:0x%%x|0x%%x], ",it->value->value.u32,it->value->mask.u32);
				break;

%s
			case OF1X_MATCH_MAX: assert(0);
				break;
		}
	}	
}
"""

ROFL_PIPELINE_PACKET_MATCHES_H_SKELETON = """
#ifndef __OF1X_PACKET_MATCHES_H__
#define __OF1X_PACKET_MATCHES_H__

#include <inttypes.h> 
#include <string.h> 
#include "rofl.h"
#include "../../../common/ternary_fields.h"

/**
* @author Marc Sune<marc.sune (at) bisdn.de>
*/

//Fwd decl
struct datapacket;
union of_packet_matches;

/* 
* Packet OF12 matching values. Matching structure expected by the pipeline for OpenFlow 1.2
*/
typedef struct{

	//Packet size
	uint32_t pkt_size_bytes;	/* Packet size in bytes */

	//Ports
	uint32_t port_in;		/* Switch input port. */
	uint32_t phy_port_in;		/* Switch physical input port. */
	
	//Associated metadata
	uint64_t metadata;		/* Metadata passed between tables. */
 
	//802
	uint64_t eth_dst;		/* Ethernet destination address. */
	uint64_t eth_src;		/* Ethernet source address. */
	uint16_t eth_type;		/* Ethernet frame type (WARNING: inner payload). */
	
	//802.1q VLAN outermost tag
	bool has_vlan;			/* VLAN flag */
	uint16_t vlan_vid;		/* VLAN id. */
	uint8_t vlan_pcp;		/* VLAN PCP. */

	//ARP
	uint16_t arp_opcode;		/* ARP opcode */
	uint64_t arp_sha;		/* ARP source hardware address */
	uint32_t arp_spa;		/* ARP source protocol address */
	uint64_t arp_tha;		/* ARP target hardware address */
	uint32_t arp_tpa;		/* ARP target protocol address */

	//IP
	uint8_t ip_proto;		/* IP protocol. */
	uint8_t ip_dscp;		/* IP DSCP (6 bits in ToS field). */
	uint8_t ip_ecn;			/* IP ECN (2 bits in ToS field). */
	
	//IPv4
	uint32_t ipv4_src;		/* IPv4 source address. */
	uint32_t ipv4_dst;		/* IPv4 destination address. */

	//TCP
	uint16_t tcp_src;		/* TCP source port. */
	uint16_t tcp_dst;		/* TCP destination port. */

	//UDP
	uint16_t udp_src;		/* UDP source port. */
	uint16_t udp_dst;		/* UDP destination port. */

	//SCTP
	uint16_t sctp_src;		/* SCTP source port. */
	uint16_t sctp_dst;		/* SCTP destination port. */


	//ICMPv4
	uint8_t icmpv4_type;		/* ICMP type. */
	uint8_t icmpv4_code;		/* ICMP code. */

	//MPLS-outermost label 
	uint32_t mpls_label;		/* MPLS label. */
	uint8_t mpls_tc;		/* MPLS TC. */
	bool mpls_bos;			/* MPLS BoS. */


	//IPv6
	uint128__t ipv6_src;		/* IPv6 source address */
	uint128__t ipv6_dst;		/* IPv6 source address */
	uint64_t ipv6_flabel;		/* IPv6 flow label */
	uint128__t ipv6_nd_target;	/* IPv6 Neighbor discovery protocol target */
	uint64_t ipv6_nd_sll;		/* IPv6 Neighbor discovery protocol source link level */
	uint64_t ipv6_nd_tll;		/* IPv6 Neighbor discovery protocol target link level */
	uint16_t ipv6_exthdr;		/* IPv6 extension pseudo header */
	
	//ICMPv6 
	uint8_t icmpv6_code;		/* ICMPv6 type */
	uint8_t icmpv6_type;		/* ICMPv6 code */

	//PBB
	uint32_t pbb_isid;		/* PBB_ISID code */
	
	//Tunnel id
	uint64_t tunnel_id;		/* Tunnel id*/

	/*
	* Extensions
	*/

	//PPPoE related extensions
	uint8_t pppoe_code;		/* PPPoE code */
	uint8_t pppoe_type;		/* PPPoE type */
	uint16_t pppoe_sid;		/* PPPoE session id */
	
	//PPP related extensions
	uint16_t ppp_proto;		/* PPPoE session id */
	
	//GTP related extensions
	uint8_t gtp_msg_type;		/* GTP message type */
	uint32_t gtp_teid;		/* GTP teid */
    
%s
}of1x_packet_matches_t;


//C++ extern C
ROFL_BEGIN_DECLS

//Init packet matches
void __of1x_init_packet_matches(struct datapacket *const pkt);

//Update packet matches after applying actions 
void __of1x_update_packet_matches(struct datapacket *const pkt);

/**
 * @brief Dump the values of packet (header values)  
 * @ingroup core_of1x
 */
void of1x_dump_packet_matches(union of_packet_matches *const pkt_matches);



//C++ extern C
ROFL_END_DECLS

#endif //OF1X_PACKET_MATCHES
"""

ROFL_PIPELINE_PACKET_MATCHES_C_SKELETON = """
#include "of1x_packet_matches.h"

#include "rofl.h"
#include "of1x_utils.h"
#include "../../../platform/packet.h"
#include "../../../util/logging.h"

/*
* Updates/Initializes packet matches based on platform information about the pkt
*/
void __of1x_update_packet_matches(datapacket_t *const pkt){
		
	of1x_packet_matches_t* matches = &pkt->matches.of1x;

	//Pkt size
	matches->pkt_size_bytes = platform_packet_get_size_bytes(pkt);
	
	//Ports
	matches->port_in = platform_packet_get_port_in(pkt);
	matches->phy_port_in = platform_packet_get_phy_port_in(pkt);	

	
	//802
	matches->eth_dst = platform_packet_get_eth_dst(pkt);
	matches->eth_src = platform_packet_get_eth_src(pkt);
	matches->eth_type = platform_packet_get_eth_type(pkt);
	
	//802.1q VLAN outermost tag
	matches->has_vlan = platform_packet_has_vlan(pkt);
	if(matches->has_vlan){
		matches->vlan_vid = platform_packet_get_vlan_vid(pkt);
		matches->vlan_pcp = platform_packet_get_vlan_pcp(pkt);
	}else{
		matches->vlan_vid = matches->vlan_pcp = 0x0;
	}

	matches->ip_proto = platform_packet_get_ip_proto(pkt);
	matches->ip_ecn = platform_packet_get_ip_ecn(pkt);
	matches->ip_dscp = platform_packet_get_ip_dscp(pkt);
	
	//ARP
	matches->arp_opcode = platform_packet_get_arp_opcode(pkt);
	matches->arp_sha = platform_packet_get_arp_sha(pkt);
	matches->arp_spa = platform_packet_get_arp_spa(pkt);
	matches->arp_tha = platform_packet_get_arp_tha(pkt);
	matches->arp_tpa = platform_packet_get_arp_tpa(pkt);

	//IPv4
	matches->ipv4_src = platform_packet_get_ipv4_src(pkt);
	matches->ipv4_dst = platform_packet_get_ipv4_dst(pkt);

	//TCP
	matches->tcp_dst = platform_packet_get_tcp_dst(pkt);
	matches->tcp_src = platform_packet_get_tcp_src(pkt);

	//UDP
	matches->udp_dst = platform_packet_get_udp_dst(pkt);
	matches->udp_src = platform_packet_get_udp_src(pkt);

	//SCTP
	matches->sctp_dst = platform_packet_get_sctp_dst(pkt);
	matches->sctp_src = platform_packet_get_sctp_src(pkt);


	//ICMPv4
	matches->icmpv4_type = platform_packet_get_icmpv4_type(pkt);
	matches->icmpv4_code = platform_packet_get_icmpv4_code(pkt);

	//MPLS-outermost label 
	matches->mpls_label = platform_packet_get_mpls_label(pkt);
	matches->mpls_tc = platform_packet_get_mpls_tc(pkt);
	matches->mpls_bos = platform_packet_get_mpls_bos(pkt);

	//PPPoE related extensions
	matches->pppoe_code = platform_packet_get_pppoe_code(pkt);
	matches->pppoe_type = platform_packet_get_pppoe_type(pkt);
	matches->pppoe_sid = platform_packet_get_pppoe_sid(pkt);

	//PPP related extensions
	matches->ppp_proto = platform_packet_get_ppp_proto(pkt);
    
	//IPv6 related extensions
	matches->ipv6_src = platform_packet_get_ipv6_src(pkt);
	matches->ipv6_dst = platform_packet_get_ipv6_dst(pkt);
	matches->ipv6_flabel = platform_packet_get_ipv6_flabel(pkt);
	matches->ipv6_nd_target = platform_packet_get_ipv6_nd_target(pkt);
	matches->ipv6_nd_sll = platform_packet_get_ipv6_nd_sll(pkt);
	matches->ipv6_nd_tll = platform_packet_get_ipv6_nd_tll(pkt);
	matches->ipv6_exthdr = platform_packet_get_ipv6_exthdr(pkt);
	
	//ICMPv6
	matches->icmpv6_type = platform_packet_get_icmpv6_type(pkt);
	matches->icmpv6_code = platform_packet_get_icmpv6_code(pkt);
	
	//PBB
	matches->pbb_isid = platform_packet_get_pbb_isid(pkt);
    
	//Tunnel id
	matches->tunnel_id = platform_packet_get_tunnel_id(pkt);

	//GTP related extensions
	matches->gtp_msg_type = platform_packet_get_gtp_msg_type(pkt);
	matches->gtp_teid = platform_packet_get_gtp_teid(pkt);
    
%s
}

/*
* Sets up pkt->matches and call update to initialize packet matches
*/
void __of1x_init_packet_matches(datapacket_t *const pkt){
	
	of1x_packet_matches_t* matches = &pkt->matches.of1x;

	//Associated metadata
	matches->metadata = 0x0; 
 
	__of1x_update_packet_matches(pkt);
}

/* 
* DEBUG/INFO dumping routines 
*/

//Dump packet matches
void of1x_dump_packet_matches(of_packet_matches_t *const pkt_matches){

	of1x_packet_matches_t *const pkt = &pkt_matches->of1x;

	ROFL_PIPELINE_DEBUG_NO_PREFIX("Packet matches [");	

	if(!pkt){
		ROFL_PIPELINE_DEBUG_NO_PREFIX("]. No matches. Probably comming from a PACKET_OUT");	
		return;
	}
	
	//Ports
	if(pkt->port_in)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("PORT_IN:%%u, ",pkt->port_in);
	if(pkt->phy_port_in)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("PHY_PORT_IN:%%u, ",pkt->phy_port_in);
	
	//Metadata
	if(pkt->metadata)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("METADATA:" PRIu64 ", ",pkt->metadata);
	
	//802	
	if(pkt->eth_src)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ETH_SRC:0x%%llx, ",(long long unsigned)pkt->eth_src);
	if(pkt->eth_dst)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ETH_DST:0x%%llx, ",(long long unsigned)pkt->eth_dst);
	if(pkt->eth_type)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ETH_TYPE:0x%%x, ",pkt->eth_type);
	//802.1q
	if(pkt->has_vlan)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("VLAN_VID:%%u, ",pkt->vlan_vid);
	if(pkt->has_vlan)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("VLAN_PCP:%%u, ",pkt->vlan_pcp);
	//ARP
	if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ARP_OPCODE:0x%%x, ",pkt->arp_opcode);
	if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ARP_SHA:0x%%llx, ",(long long unsigned)pkt->arp_sha);
	if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ARP_SPA:0x%%x, ",pkt->arp_spa);
	if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ARP_THA:0x%%llx, ",(long long unsigned)pkt->arp_tha);
	if(pkt->eth_type == OF1X_ETH_TYPE_ARP)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ARP_TPA:0x%%x, ",pkt->arp_tpa);
	//IP/IPv4
	if((pkt->eth_type == OF1X_ETH_TYPE_IPV4 || pkt->eth_type == OF1X_ETH_TYPE_IPV6) && pkt->ip_proto)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IP_PROTO:%%u, ",pkt->ip_proto);

	if((pkt->eth_type == OF1X_ETH_TYPE_IPV4 || pkt->eth_type == OF1X_ETH_TYPE_IPV6) && pkt->ip_ecn)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IP_ECN:0x%%x, ",pkt->ip_ecn);
	
	if((pkt->eth_type == OF1X_ETH_TYPE_IPV4 || pkt->eth_type == OF1X_ETH_TYPE_IPV6) && pkt->ip_dscp)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IP_DSCP:0x%%x, ",pkt->ip_dscp);
	
	if(pkt->ipv4_src)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV4_SRC:0x%%x, ",pkt->ipv4_src);
	if(pkt->ipv4_dst)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV4_DST:0x%%x, ",pkt->ipv4_dst);
	//TCP
	if(pkt->tcp_src)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("TCP_SRC:%%u, ",pkt->tcp_src);
	if(pkt->tcp_dst)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("TCP_DST:%%u, ",pkt->tcp_dst);
	//UDP
	if(pkt->udp_src)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("UDP_SRC:%%u, ",pkt->udp_src);
	if(pkt->udp_dst)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("UDP_DST:%%u, ",pkt->udp_dst);

	//SCTP
	if(pkt->sctp_src)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("SCTP_SRC:%%u, ",pkt->sctp_src);
	if(pkt->sctp_dst)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("SCTP_DST:%%u, ",pkt->sctp_dst);

	//ICMPV4
	if(pkt->ip_proto == OF1X_IP_PROTO_ICMPV4)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ICMPV4_TYPE:%%u, ICMPV4_CODE:%%u, ",pkt->icmpv4_type,pkt->icmpv4_code);
	
	//IPv6
	if( UINT128__T_LO(pkt->ipv6_src) || UINT128__T_HI(pkt->ipv6_src) )
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV6_SRC:0x%%lx:%%lx, ",UINT128__T_HI(pkt->ipv6_src),UINT128__T_LO(pkt->ipv6_src));
	if( UINT128__T_LO(pkt->ipv6_dst) || UINT128__T_HI(pkt->ipv6_dst) )
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV6_DST:0x%%lx:%%lx, ",UINT128__T_HI(pkt->ipv6_dst),UINT128__T_LO(pkt->ipv6_dst));
	if(pkt->eth_type == OF1X_ETH_TYPE_IPV6)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV6_FLABEL:0x%%lu, ",pkt->ipv6_flabel);
	if(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV6_ND_TARGET:0x%%lx:%%lx, ",UINT128__T_HI(pkt->ipv6_nd_target),UINT128__T_LO(pkt->ipv6_nd_target));
	if(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6) //NOTE && pkt->icmpv6_type ==?
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV6_ND_SLL:0x%%llx, ",pkt->ipv6_nd_sll);
	if(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6) //NOTE && pkt->icmpv6_type ==?
		ROFL_PIPELINE_DEBUG_NO_PREFIX("IPV6_ND_TLL:0x%%llx, ",pkt->ipv6_nd_tll);
	/*TODO IPV6 exthdr*/
	/*nd_target nd_sll nd_tll exthdr*/
	
	//ICMPv6
	if(pkt->ip_proto == OF1X_IP_PROTO_ICMPV6)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("ICMPV6_TYPE:%%lu, ICMPV6_CODE:%%lu, ",pkt->icmpv6_type,pkt->icmpv6_code);
	
	//MPLS	
   	if(pkt->eth_type == OF1X_ETH_TYPE_MPLS_UNICAST || pkt->eth_type == OF1X_ETH_TYPE_MPLS_MULTICAST )
		ROFL_PIPELINE_DEBUG_NO_PREFIX("MPLS_LABEL:0x%%x, MPLS_TC:0x%%x, MPLS_BOS:%%u",pkt->mpls_label, pkt->mpls_tc, pkt->mpls_bos);
	//PPPoE
	if(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_DISCOVERY || pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION ){
		ROFL_PIPELINE_DEBUG_NO_PREFIX("PPPOE_CODE:0x%%x, PPPOE_TYPE:0x%%x, PPPOE_SID:0x%%x, ",pkt->pppoe_code, pkt->pppoe_type,pkt->pppoe_sid);
		//PPP
		if(pkt->eth_type == OF1X_ETH_TYPE_PPPOE_SESSION)
			ROFL_PIPELINE_DEBUG_NO_PREFIX("PPP_PROTO:0x%%x, ",pkt->ppp_proto);
				
	}

	//PBB
	if(pkt->pbb_isid)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("PBB_ISID:%%u,",pkt->pbb_isid);
	//Tunnel id
	if(pkt->tunnel_id)
		ROFL_PIPELINE_DEBUG_NO_PREFIX("TUNNEL ID:0x%%llx, ",(long long unsigned)pkt->tunnel_id);
	
	//GTP
	if(pkt->ip_proto == OF1X_IP_PROTO_UDP && pkt->udp_dst == OF1X_UDP_DST_PORT_GTPU){
		ROFL_PIPELINE_DEBUG_NO_PREFIX("GTP_MSG_TYPE:%%u, GTP_TEID:0x%%x, ",pkt->gtp_msg_type, pkt->gtp_teid);
	}

%s
	ROFL_PIPELINE_DEBUG_NO_PREFIX("]\\n");	
}
"""

ROFL_PIPELINE_PLATFORM_PACKET_H = """
#ifndef PLATFORM_PACKET_HOOKS_AUTOGENERATED
#define PLATFORM_PACKET_HOOKS_AUTOGENERATED

#include <stdint.h>

#include "rofl.h"
#include "../common/datapacket.h"
#include "../common/ternary_fields.h"
#include "../switch_port.h"

//C++ extern C
ROFL_BEGIN_DECLS

%s

//C++ extern C
ROFL_END_DECLS

#endif //PLATFORM_PACKET_HOOKS_AUTOGENERATED
"""

COXMATCH_DISPLAY_SKELETON = """
			case OFPXMT_OFX_%(header_upper)s_%(field_upper)s:
				{
					info.assign(vas("OXM-TLV [%%s:%%s] => [%%d] hm:%%d len:%%d padded-len:%%d",
							class2desc(get_oxm_class()),
							type2desc(get_oxm_class(), get_oxm_field()),
							uint%(length)s_value(),
							get_oxm_hasmask(),
							get_oxm_length(),
							length()));
				}
				break;
"""
    
def generate_oxm_header_code(fields):
    header = fields[0]['header']
    code = ""
    for field in fields:
        code += OXM_HEADER_SKELETON % field
    return OXM_HEADER_BEGIN_END % {'code':code, 'header': header}
  
def generate_oxm_code(fields):
    code = OXM_CODE_BEGIN % fields[0]
    for field in fields:
        code += OXM_CODE_SKELETON % field
    return code  

def generate_makefile_am(fields):
    return MAKEFILE_AM_SKELETON % fields[0]

    
def generate_openflow_experimental(fields):
    field_id = 27
    code = ""
    for field in fields:
        field['field_id'] = field_id
        code += "\tOFPXMT_OFX_%(header_upper)s_%(field_upper)s = %(field_id)d,\n" % field
        field_id += 1
    return OPENFLOW_EXPERIMENTAL_SKELETON % code
    
def generate_openflow_pipeline_match_h(fields):
    code = ""
    for field in fields:
        code += "\tOF1X_MATCH_%(header_upper)s_%(field_upper)s,\n" % field
    code = OPENFLOW_PIPELINE_MATCH_IDS_SKELETON % code
    
    code2 = ""
    for field in fields:
        code2 += "of1x_match_t* of1x_init_%(header)s_%(field)s_match(of1x_match_t* prev, of1x_match_t* next, uint%(length)s_t value);\n" % field
        
    return ROFL_PIPELINE_MATCH_AUTOGENERATED_H_SKELOTON % (code, code2)
    
def generate_openflow_pipeline_match_c(fields):
    code  = """#include <assert.h>
#include "rofl.h"
#include "of1x_utils.h"
#include "../../../platform/packet.h"
#include "../../../util/logging.h"
#include "of1x_match.h"
#include "of1x_match_autogenerated.h"
#include "../../../common/datapacket.h"
#include "../../../platform/memory.h"
#include "../../../util/logging.h"
\n\n"""
    
    code2 = ""
    for field in fields:
        code2 += "\t\tcase OF1X_MATCH_%(header_upper)s_%(field_upper)s: return of1x_init_%(header)s_%(field)s_match(NULL,NULL,match->value->value.u%(length)s);\n" % field
    code += ROFL_PIPELINE_MATCH_COPY_SKELETON % code2
    
    code2 = ""
    for field in fields:
        #field['lower_protocol'] = 'OF1X_IP_PROTO_UDP' # TODO
        #field['lower_protocol_field'] = 'ip_proto' # TODO
        #code2 += """\t\tcase OF1X_MATCH_%(header_upper)s_%(field_upper)s: if (!(pkt->%(lower_protocol_field)s == %(lower_protocol)s)) return false;
        #\t\t\t\treturn __utern_compare%(length)s(it->value,pkt->%(header)s_%(field)s);\n""" % field
        code2 += """\t\tcase OF1X_MATCH_%(header_upper)s_%(field_upper)s:\n\t\t\t\treturn __utern_compare%(length)s(it->value,pkt->%(header)s_%(field)s);\n""" % field
    code += ROFL_PIPELINE_MATCH_CHECK_SKELETON % code2
    
    code1 = ""
    for field in fields:
        code1 += ROFL_PIPELINE_MATCH_INIT_SKELETON % field
    code += code1

    code2 = ""
    for field in fields:
        code2 += """\t\t\tcase OF1X_MATCH_%(header_upper)s_%(field_upper)s:  ROFL_PIPELINE_DEBUG_NO_PREFIX("[%(header_upper)s_%(field_upper)s:%%u]", it->value->value.u%(length)s);\n\t\t\t\tbreak;\n""" % field
    code += ROFL_PIPELINE_MATCH_DUMP_SKELETON % code2
    return code
    
def generate_openflow_pipeline_packet_matches_h(fields):
    code = ""
    for field in fields:
        code += "\tuint%(length)s_t %(header)s_%(field)s;\n" % field
    return ROFL_PIPELINE_PACKET_MATCHES_H_SKELETON % code

def generate_openflow_pipeline_packet_matches_c(fields):
    code = ""
    for field in fields:
        code += "\tmatches->%(header)s_%(field)s = platform_packet_get_%(header)s_%(field)s(pkt);\n" % field
        
    code2 = ""
    for field in fields:
        code2 += """\tif(pkt->%(header)s_%(field)s) \t\tROFL_PIPELINE_DEBUG_NO_PREFIX("%(header_upper)s_%(field_upper)s:%%u, ",pkt->%(header)s_%(field)s);\n""" % field
    
    return ROFL_PIPELINE_PACKET_MATCHES_C_SKELETON % (code, code2)
    
def generate_openflow_pipeline_platform_packet_h(fields):
    code = ""
    for field in fields:
        code += "uint%(length)s_t platform_packet_get_%(header)s_%(field)s(datapacket_t *const pkt);\n" % field
        code += "void platform_packet_set_%(header)s_%(field)s(datapacket_t* pkt, uint%(length)s_t code);\n" % field
    return ROFL_PIPELINE_PLATFORM_PACKET_H % code
    
def generate_openflow_common_coxmatch_c(fields):
    skeleton = read_template("templates/rofl_coxmatches.c.template")
    
    code0 = ""
    for field in fields:
        code0 += COXMATCH_DISPLAY_SKELETON % field
        
    code1 = ""
    for field in fields:
        code1 +=  """	{ OFPXMT_OFX_%(header_upper)s_%(field_upper)s, 		"%(header_upper)s_%(field_upper)s" },\n"""  % field
    return skeleton % (code0, code1)
    
def generate_oxm_experimental_part(fields):
    header = fields[0]['header']
    location = ROFL_DIR + '/common/openflow/experimental/matches/'
        
    generate_file(location + '%s_matches.h' % header, generate_oxm_header_code(fields))
    generate_file(location + '%s_matches.cc' % header, generate_oxm_code(fields))
    generate_file(location + 'Makefile.am', generate_makefile_am(fields))
    
def generate_rofl_pipeline_part(fields):
    location = ROFL_DIR + '/datapath/pipeline/openflow/openflow1x/pipeline/'
    generate_file(location + 'of1x_match_autogenerated.h', generate_openflow_pipeline_match_h(fields))
    generate_file(location + 'of1x_match_autogenerated.c', generate_openflow_pipeline_match_c(fields))
    generate_file(location + 'of1x_packet_matches.h', generate_openflow_pipeline_packet_matches_h(fields))
    generate_file(location + 'of1x_packet_matches.c', generate_openflow_pipeline_packet_matches_c(fields))
    
    generate_file(ROFL_DIR + '/datapath/pipeline/platform/packet_autogenerated.h', generate_openflow_pipeline_platform_packet_h(fields))
    
    
def generate_rofl_matches(fields):
    fields = approve_fields_with_attribute(fields, 'field')
    add_fields_properties(fields)
    
    generate_oxm_experimental_part(fields)
    generate_file(ROFL_DIR + '/common/openflow/openflow_experimental.h', generate_openflow_experimental(fields)) # causes long time recompile
    generate_file(ROFL_DIR + '/common/openflow/coxmatch.cc', generate_openflow_common_coxmatch_c(fields))
    generate_rofl_pipeline_part(fields)
    
    
    

if __name__ == "__main__":
    generate_rofl_matches([{'header': 'pad_tag', 'field':'a', 'length':'8'}, 
                             {'header': 'pad_tag', 'field':'b', 'length':'16'}])