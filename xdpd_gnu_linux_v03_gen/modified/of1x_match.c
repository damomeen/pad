#include <assert.h>
#include "of1x_match.h"

#include "../../../common/datapacket.h"
#include "../../../platform/memory.h"
#include "../../../util/logging.h"

/*
* Initializers 
*/

#define OF1X_MIN_VERSION OF_VERSION_10
#define OF1X_MAX_VERSION OF_VERSION_13

//Phy
inline of1x_match_t* of1x_init_port_in_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IN_PORT; 
	match->value = __init_utern32(value,OF1X_4_BYTE_MASK); //No wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

inline of1x_match_t* of1x_init_port_in_phy_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IN_PHY_PORT; 
	match->value = __init_utern32(value,OF1X_4_BYTE_MASK); //No wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

//METADATA
inline of1x_match_t* of1x_init_metadata_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value, uint64_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_METADATA; 
	match->value = __init_utern64(value, mask);
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_8_BYTE_MASK) != OF1X_8_BYTE_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}

//ETHERNET
inline of1x_match_t* of1x_init_eth_dst_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value, uint64_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ETH_DST; 
	match->value = __init_utern64(value&OF1X_48_BITS_MASK, mask&OF1X_48_BITS_MASK); //Enforce mask bits are always 00 for the first bits

	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_48_BITS_MASK) != OF1X_48_BITS_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_eth_src_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value, uint64_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ETH_SRC; 
	match->value = __init_utern64(value&OF1X_48_BITS_MASK, mask&OF1X_48_BITS_MASK); //Enforce mask bits are always 00 for the first bits
	match->prev = prev;
	match->next = next;
	
	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_48_BITS_MASK) != OF1X_48_BITS_MASK )
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_eth_type_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ETH_TYPE; 
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //No wildcard 
	match->prev = prev;
	match->next = next;
	
	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards
	
	return match;
}

//8021.q
inline of1x_match_t* of1x_init_vlan_vid_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value, uint16_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_VLAN_VID; 
	//Setting values; note that value includes the flag HAS_VLAN in the 13th bit
	//The mask is set to be strictly 12 bits, so only matching the VLAN ID itself
	match->value = __init_utern16(value&OF1X_13_BITS_MASK,mask&OF1X_VLAN_ID_MASK);
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_13_BITS_MASK) != OF1X_13_BITS_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_vlan_pcp_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_VLAN_PCP; 
	match->value = __init_utern8(value&OF1X_3_BITS_MASK,OF1X_3_BITS_MASK); //Ensure only 3 bit value, no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards
	
	return match;
}

//MPLS
inline of1x_match_t* of1x_init_mpls_label_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_MPLS_LABEL; 
	match->value = __init_utern32(value&OF1X_20_BITS_MASK,OF1X_20_BITS_MASK); //no wildcard?? wtf! 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards
	
	return match;
}
inline of1x_match_t* of1x_init_mpls_tc_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_MPLS_TC; 
	match->value = __init_utern8(value&OF1X_3_BITS_MASK,OF1X_3_BITS_MASK); //Ensure only 3 bit value, no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards
	
	return match;
}
inline of1x_match_t* of1x_init_mpls_bos_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_MPLS_BOS; 
	match->value = __init_utern8(value&OF1X_1_BIT_MASK,OF1X_1_BIT_MASK); //Ensure only 1 bit value, no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_13;	//First supported in OF1.3
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards
	
	return match;
}

//ARP
inline of1x_match_t* of1x_init_arp_opcode_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){

	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ARP_OP;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //No wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0 (1.0: lower 8bits of opcode)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_arp_tha_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value, uint64_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ARP_THA;
	match->value = __init_utern64(value&OF1X_48_BITS_MASK, mask&OF1X_48_BITS_MASK); //Enforce mask bits are always 00 for the first bits

	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_48_BITS_MASK) != OF1X_48_BITS_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_arp_sha_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value, uint64_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ARP_SHA;
	match->value = __init_utern64(value&OF1X_48_BITS_MASK, mask&OF1X_48_BITS_MASK); //Enforce mask bits are always 00 for the first bits
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_48_BITS_MASK) != OF1X_48_BITS_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_arp_tpa_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ARP_TPA;
	match->value = __init_utern32(value,mask);
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( mask != OF1X_4_BYTE_MASK )
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_arp_spa_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ARP_SPA;
	match->value = __init_utern32(value,mask);
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( mask != OF1X_4_BYTE_MASK )
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}

//NW
inline of1x_match_t* of1x_init_nw_proto_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_NW_PROTO; 
	match->value = __init_utern8(value,OF1X_1_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF_VERSION_10; //Last supported in OF1.0
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_nw_src_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_NW_SRC;
	match->value = __init_utern32(value,mask); 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF_VERSION_10; //Last supported in OF1.0
	if( (mask&OF1X_4_BYTE_MASK) != OF1X_4_BYTE_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_nw_dst_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_NW_DST;
	match->value = __init_utern32(value,mask); 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF_VERSION_10; //Last supported in OF1.0
	if( (mask&OF1X_4_BYTE_MASK) != OF1X_4_BYTE_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}

//IPv4
inline of1x_match_t* of1x_init_ip4_src_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IPV4_SRC;
	match->value = __init_utern32(value,mask); 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_4_BYTE_MASK) != OF1X_4_BYTE_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_ip4_dst_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IPV4_DST;
	match->value = __init_utern32(value,mask); 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_4_BYTE_MASK) != OF1X_4_BYTE_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_ip_proto_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IP_PROTO; 
	match->value = __init_utern8(value,OF1X_1_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_ip_dscp_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IP_DSCP; 
	match->value = __init_utern8(value&OF1X_6_BITS_MASK,OF1X_6_BITS_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0 (ToS)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

inline of1x_match_t* of1x_init_ip_ecn_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IP_ECN; 
	match->value = __init_utern8(value&OF1X_2_BITS_MASK,OF1X_2_BITS_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

//IPv6
inline of1x_match_t* of1x_init_ip6_src_match(of1x_match_t* prev, of1x_match_t* next, uint128__t value, uint128__t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	uint128__t fixed_mask = {{0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff}};
	match->type = OF1X_MATCH_IPV6_SRC;
	match->value = __init_utern128(value,mask); 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if(memcmp(&fixed_mask,&mask, sizeof(mask)) != 0)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_ip6_dst_match(of1x_match_t* prev, of1x_match_t* next, uint128__t value, uint128__t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	uint128__t fixed_mask = {{0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff}};
	match->type = OF1X_MATCH_IPV6_DST;
	match->value = __init_utern128(value,mask); 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if(memcmp(&fixed_mask,&mask, sizeof(mask)) != 0)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}
inline of1x_match_t* of1x_init_ip6_flabel_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IPV6_FLABEL;
	match->value = __init_utern64(value&OF1X_20_BITS_MASK,OF1X_20_BITS_MASK); // ensure 20 bits. No wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_ip6_nd_target_match(of1x_match_t* prev, of1x_match_t* next, uint128__t value){
	
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	uint128__t mask = {{0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff}};
	
	match->type = OF1X_MATCH_IPV6_ND_TARGET;
	match->value = __init_utern128(value,mask); //No wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_ip6_nd_sll_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IPV6_ND_SLL;
	match->value = __init_utern64(value & OF1X_48_BITS_MASK, OF1X_48_BITS_MASK); //ensure 48 bits. No wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_ip6_nd_tll_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IPV6_ND_TLL;
	match->value = __init_utern64(value & OF1X_48_BITS_MASK, OF1X_48_BITS_MASK); //ensure 48 bits. No wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_ip6_exthdr_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value, uint16_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_IPV6_EXTHDR;
	match->value = __init_utern16(value&OF1X_9_BITS_MASK, mask & OF1X_9_BITS_MASK );  //ensure 9 bits, with Wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_13;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_9_BITS_MASK) != OF1X_9_BITS_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}

//ICMPV6
inline of1x_match_t* of1x_init_icmpv6_type_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ICMPV6_TYPE;
	match->value = __init_utern8(value,OF1X_1_BYTE_MASK);
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_icmpv6_code_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ICMPV6_CODE;
	match->value = __init_utern8(value,OF1X_1_BYTE_MASK);
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

//TCP
inline of1x_match_t* of1x_init_tcp_src_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_TCP_SRC;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards


	return match;
}
inline of1x_match_t* of1x_init_tcp_dst_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_TCP_DST;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
//UDP
inline of1x_match_t* of1x_init_udp_src_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_UDP_SRC;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_udp_dst_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_UDP_DST;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

//SCTP
inline of1x_match_t* of1x_init_sctp_src_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_SCTP_SRC;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards


	return match;
}
inline of1x_match_t* of1x_init_sctp_dst_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_SCTP_DST;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

//TP
inline of1x_match_t* of1x_init_tp_src_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_TP_SRC;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF_VERSION_10;	//Last supported in OF1.0
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_tp_dst_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_TP_DST;
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_10;	//First supported in OF1.0
	match->ver_req.max_ver = OF_VERSION_10;	//Last supported in OF1.0
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
//ICMPv4
inline of1x_match_t* of1x_init_icmpv4_type_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ICMPV4_TYPE; 
	match->value = __init_utern8(value,OF1X_1_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_icmpv4_code_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_ICMPV4_CODE; 
	match->value = __init_utern8(value,OF1X_1_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}

//PBB
inline of1x_match_t* of1x_init_pbb_isid_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_PBB_ISID;
	match->value = __init_utern32(value&OF1X_3_BYTE_MASK, mask&OF1X_3_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_13;	//First supported in OF1.3
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( (mask&OF1X_3_BYTE_MASK) == OF1X_3_BYTE_MASK)
		match->has_wildcard = false;
	else
		match->has_wildcard = false;

	return match;
}

//Tunnel Id
inline of1x_match_t* of1x_init_tunnel_id_match(of1x_match_t* prev, of1x_match_t* next, uint64_t value, uint64_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_TUNNEL_ID; 
	match->value = __init_utern64(value, mask); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_13;	//First supported in OF1.3
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if(mask != OF1X_8_BYTE_MASK)
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}

//Add more here...

/* Extensions */

//PPPoE
inline of1x_match_t* of1x_init_pppoe_code_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_PPPOE_CODE; 
	match->value = __init_utern8(value&OF1X_1_BYTE_MASK,OF1X_1_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2 (extensions)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_pppoe_type_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_PPPOE_TYPE; 
	match->value = __init_utern8(value&OF1X_4_BITS_MASK,OF1X_4_BITS_MASK); //Ensure only 4 bit value, no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2 (extensions)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_pppoe_session_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_PPPOE_SID; 
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2 (extensions)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting w
	return match;
}
//PPP
inline of1x_match_t* of1x_init_ppp_prot_match(of1x_match_t* prev, of1x_match_t* next, uint16_t value){

	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_PPP_PROT; 
	match->value = __init_utern16(value,OF1X_2_BYTE_MASK); //no wildcard 
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2 (extensions)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
//GTP
inline of1x_match_t* of1x_init_gtp_msg_type_match(of1x_match_t* prev, of1x_match_t* next, uint8_t value){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_GTP_MSG_TYPE;
	match->value = __init_utern8(value,OF1X_1_BYTE_MASK); //no wildcard
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2 (extensions)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	match->has_wildcard = false;		//Not accepting wildcards

	return match;
}
inline of1x_match_t* of1x_init_gtp_teid_match(of1x_match_t* prev, of1x_match_t* next, uint32_t value, uint32_t mask){
	of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
	match->type = OF1X_MATCH_GTP_TEID;
	match->value = __init_utern32(value, mask);
	match->prev = prev;
	match->next = next;

	//Set fast validation flags	
	match->ver_req.min_ver = OF_VERSION_12;	//First supported in OF1.2 (extensions)
	match->ver_req.max_ver = OF1X_MAX_VERSION;		//No limitation on max
	if( mask != OF1X_4_BYTE_MASK )
		match->has_wildcard = true;
	else
		match->has_wildcard = false;

	return match;
}

//Add more here...

/* Instruction groups init and destroy */
void __of1x_init_match_group(of1x_match_group_t* group){

	memset(group,0,sizeof(of1x_match_group_t));
	
	//Set min max 
	group->ver_req.min_ver = OF1X_MIN_VERSION;
	group->ver_req.max_ver = OF1X_MAX_VERSION;
}

void __of1x_destroy_match_group(of1x_match_group_t* group){
	of1x_match_t *match;

	if (!group->head)
		return;

	match = group->head;

	while (match){
		of1x_match_t *next = match->next;
		of1x_destroy_match(match);
		match = next;
	}

	group->head = NULL; 
	group->tail = NULL; 
}



void __of1x_match_group_push_back(of1x_match_group_t* group, of1x_match_t* match){

	if (!group || !match)
		return;

	match->next = match->prev = NULL; 

	if(!group->head){
		group->head = match;
	}else{
		match->prev = group->tail;
		group->tail->next = match;
	}

	//Deduce new tail and update validation flags and num of elements
	do{
		//Update fast validation flags (required versions)
		if(group->ver_req.min_ver < match->ver_req.min_ver)
			group->ver_req.min_ver = match->ver_req.min_ver;
		if(group->ver_req.max_ver > match->ver_req.max_ver)
			group->ver_req.max_ver = match->ver_req.max_ver;

		if(match->has_wildcard)
			group->has_wildcard = true;

		group->num_elements++;

		if(match->next == NULL)
			break;
		else	
			match = match->next;
	}while(1);
	
	//Add new tail
	group->tail = match;
}

/* 
* Whole (linked list) Match copy -> this should be deprecated in favour of the match group
*/
of1x_match_t* __of1x_copy_matches(of1x_match_t* matches){

	of1x_match_t* prev, *curr, *it, *copy;
	
	if(!matches)
		return NULL;
	
	for(prev=NULL,copy=NULL, it=matches; it; it = it->next){

		curr = __of1x_copy_match(it);

		if(!curr){
			//FIXME: attempt to delete previous
			return NULL;
		}	

		//Set initial match
		if(!copy)
			copy = curr;

		if(prev)
			prev->next = curr;

		curr->prev = prev;	
		prev = curr;
	}

	return copy;	
}



/*
* Try to find the largest common value among match1 and match2, being ALWAYS match2 with a more strict mask 
*/
inline of1x_match_t* __of1x_get_alike_match(of1x_match_t* match1, of1x_match_t* match2){
	utern_t* common_tern = NULL;	

	if( match1->type != match2->type )
		return NULL;	

	common_tern = __utern_get_alike(*match1->value,*match2->value);

	if(common_tern){
		of1x_match_t* match = (of1x_match_t*)platform_malloc_shared(sizeof(of1x_match_t));
		match->value = common_tern;
		match->type = match1->type;
		match->next = NULL;
		match->prev = NULL;
		return match;
	}
	return NULL;
}
/*
* Common destructor
*/
void of1x_destroy_match(of1x_match_t* match){
	__destroy_utern(match->value);
	platform_free_shared(match);
}

/*
*
* Matching routines...
* 
*/

//Compare matches
inline bool __of1x_equal_matches(of1x_match_t* match1, of1x_match_t* match2){

	if( match1->type != match2->type )
		return false; 

	return __utern_equals(match1->value,match2->value);
}

//Finds out if sub_match is a submatch of match
inline bool __of1x_is_submatch(of1x_match_t* sub_match, of1x_match_t* match){

	if( match->type != sub_match->type )
		return false; 
	
	return __utern_is_contained(sub_match->value,match->value);
}

