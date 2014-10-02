from config import XDPD_GNU_LINUX_DIR, XDPD_OPENFLOW, TEMPLATES_DIR
from pad_utils import read_template, generate_file, add_fields_properties
import copy

INIT_SKELETON = """
	for (i=0;i<MAX_%(header_upper)s_FRAMES;i++){
		headers[FIRST_%(header_upper)s_FRAME_POS+i].frame = new rofl::f%(header)sframe(NULL, 0);
		headers[FIRST_%(header_upper)s_FRAME_POS+i].type = HEADER_TYPE_%(header_upper)s;
	}
"""

GETTER_SKELETON = """
rofl::f%(header)sframe* static_pktclassifier::%(header)s(int idx) const
{
	unsigned int pos;

	if(idx > (int)MAX_%(header_upper)s_FRAMES)
		return NULL;

	if(idx < 0) //Inner most
		pos = FIRST_%(header_upper)s_FRAME_POS + num_of_headers[HEADER_TYPE_%(header_upper)s] - 1;
	else
		pos = FIRST_%(header_upper)s_FRAME_POS + idx;

	//Return the index
	if(headers[pos].present)
		return (rofl::f%(header)sframe*) headers[pos].frame;
	return NULL;
}
"""

PARSER_SKELETON = """
void static_pktclassifier::parse_%(header)s( uint8_t *data, size_t datalen){

	if (datalen < sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t)) { return; }

	//Set frame
	unsigned int num_of_%(header)s = num_of_headers[HEADER_TYPE_%(header_upper)s];
	headers[FIRST_%(header_upper)s_FRAME_POS + num_of_%(header)s].frame->reset(data, datalen);
	headers[FIRST_%(header_upper)s_FRAME_POS + num_of_%(header)s].present = true;
	num_of_headers[HEADER_TYPE_%(header_upper)s] = num_of_%(header)s+1;

	//Set reference
	//rofl::f%(header)sframe *%(header)s = (rofl::f%(header)sframe*) headers[FIRST_%(header_upper)s_FRAME_POS + num_of_%(header)s].frame;

	//Increment pointers and decrement remaining payload size
	data += sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t);
	datalen -= sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t);

	if (datalen > 0){
		//TODO: something
	}
}
"""

ETHER_PARSE_SKELETON = """
		case rofl::f%(header)sframe::%(header_upper)s_%(lower_protocol_field_upper)s:
			{
				parse_%(header)s(data,datalen);
			}
			break;
"""

POP_SKELETON = """
void static_pktclassifier::pop_%(header)s(uint16_t ether_type)
{
	rofl::fetherframe* ether_header;
	unsigned int current_length;	

	if (num_of_headers[HEADER_TYPE_%(header_upper)s] == 0 || !headers[FIRST_%(header_upper)s_FRAME_POS].present)
		return;
	
	rofl::f%(header)sframe* %(header)s = (rofl::f%(header)sframe*) headers[FIRST_%(header_upper)s_FRAME_POS].frame;
	
	if (!%(header)s)
		return;

	//Recover the ether(0)
	ether_header = ether(0);
	current_length = ether_header->framelen(); 
	
	pkt_pop(/*offset=*/sizeof(struct rofl::fetherframe::eth_hdr_t), sizeof(rofl::f%(header)sframe::%(header)s_hdr_t));

	//Take header out
	pop_header(HEADER_TYPE_%(header_upper)s, FIRST_%(header_upper)s_FRAME_POS, FIRST_%(header_upper)s_FRAME_POS+MAX_%(header_upper)s_FRAMES);

	ether_header->shift_right(sizeof(rofl::f%(header)sframe::%(header)s_hdr_t));
	ether_header->set_dl_type(ether_type);
	ether_header->reset(ether_header->soframe(), current_length - sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t));
}
"""

PUSH_SKELETON = """
rofl::f%(header)sframe* static_pktclassifier::push_%(header)s(uint16_t ether_type){
	
	rofl::fetherframe* ether_header;
	unsigned int current_length;

	if ((NULL == ether(0)) || num_of_headers[HEADER_TYPE_%(header_upper)s] == MAX_%(header_upper)s_FRAMES ){
		return NULL;
	}
	
	//Recover the ether(0)
	ether_header = ether(0);
	current_length = ether_header->framelen(); 
	
	if(!is_classified)
		classify(); // this ensures that ether(0) exists

	/*
	 * this invalidates ether(0), as it shifts ether(0) to the left
	 */
	if (pkt_push(sizeof(rofl::fetherframe::eth_hdr_t), sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t)) == ROFL_FAILURE){
		// TODO: log error
		return 0;
	}

	/*
	 * adjust ether(0): move one tag to the left
	 */
	ether_header->shift_left(sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t));

	/*
	 * append the new frame 
	 */
	push_header(HEADER_TYPE_%(header_upper)s, FIRST_%(header_upper)s_FRAME_POS, FIRST_%(header_upper)s_FRAME_POS+MAX_%(header_upper)s_FRAMES);
	
	//Now reset frame 
	ether_header->reset(ether_header->soframe(), current_length + sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t));
	
	headers[FIRST_%(header_upper)s_FRAME_POS].frame->reset(ether_header->soframe() + sizeof(struct rofl::fetherframe::eth_hdr_t), current_length + sizeof(struct rofl::f%(header)sframe::%(header)s_hdr_t) - sizeof(struct rofl::fetherframe::eth_hdr_t));
    
    rofl::f%(header)sframe* %(header)s_header = this->%(header)s(0);
	ether_header->set_dl_type(ether_type);
	
	return %(header)s_header;
}
"""

GET_SKELETON = """
uint%(length)s_t
platform_packet_get_%(header)s_%(field)s(datapacket_t * const pkt)
{
	datapacketx86 *pack = (datapacketx86*)pkt->platform_state;
	if (NULL == pack) return 0;
	if (NULL != pack->headers->%(header)s(0))
		return pack->headers->%(header)s(0)->get_%(field)s();
	return 0;
}
"""

SET_SKELETON = """
void
platform_packet_set_%(header)s_%(field)s(datapacket_t* pkt, uint%(length)s_t %(field)s)
{
	datapacketx86 *pack = (datapacketx86*)pkt->platform_state;
	if ((NULL == pack) || (NULL == pack->headers->%(header)s(0))) return;
	pack->headers->%(header)s(0)->set_%(field)s(%(field)s);
}
"""

POP2_SKELETON = """
void
platform_packet_pop_%(header)s(datapacket_t* pkt, uint16_t ether_type)
{
	datapacketx86 *pack = (datapacketx86*)pkt->platform_state;
	if (NULL == pack) return;
	pack->headers->pop_%(header)s(ether_type);
}
"""

PUSH2_SKELETON = """
void
platform_packet_push_%(header)s(datapacket_t* pkt, uint16_t ether_type)
{
	datapacketx86 *pack = (datapacketx86*)pkt->platform_state;
	if (NULL == pack) return;
	pack->headers->push_%(header)s(ether_type);
}
"""

PACKET_CODE_FILE_SKELETON = """
#include <rofl/datapath/pipeline/common/datapacket.h>
#include <rofl/common/protocols/f%sframe.h>
#include "../io/datapacketx86.h"

using namespace rofl;
using namespace xdpd::gnu_linux;
"""

EXPERIMENTAL_INCLUDES_SKELETON = """
#include <rofl/common/openflow/experimental/matches/%s_matches.h>
#include <rofl/common/openflow/experimental/actions/%s_actions.h>
"""

MATCH_TRANSLATION_SKELETON = """
	try {
		coxmatch_ofx_%(header)s_%(field)s oxm_%(header)s_%(field)s(
				ofmatch.get_const_match(OFPXMC_EXPERIMENTER, OFPXMT_OFX_%(header_upper)s_%(field_upper)s));

		of1x_match_t *match = of1x_init_%(header)s_%(field)s_match(
								/*prev*/NULL,
								/*next*/NULL,
								oxm_%(header)s_%(field)s.get_%(header)s_%(field)s());

		of1x_add_match_to_entry(entry, match);
	} catch (eOFmatchNotFound& e) {}
"""

MATCH_SET_SKELETON = """
				case OFPXMT_OFX_%(header_upper)s_%(field_upper)s:
				{
					field.u%(length)s = oxm.uint%(length)s_value();
					action = of1x_init_packet_action( OF1X_AT_SET_FIELD_%(header_upper)s_%(field_upper)s, field, NULL, NULL);
				}
					break;
"""

ACTION_SET_SKELETON = """
				case cofaction_%(action)s_%(header)s::OFXAT_%(action_upper)s_%(header_upper)s: {
					cofaction_%(action)s_%(header)s paction(eaction);
					field.u16 = be16toh(paction.eoac_%(action)s_%(header)s->expbody.ethertype);
					action = of1x_init_packet_action( OF1X_AT_%(action_upper)s_%(header_upper)s, field, NULL, NULL);
				} break;
"""

REVERSE_MATCH_SKELETON = """
		case OF1X_MATCH_%(header_upper)s_%(field_upper)s:
			match.insert(coxmatch_ofx_%(header)s_%(field)s(m->value->value.u%(length)s));
			break;
"""

REVERSE_ACTION_SKELETON = """
	case OF1X_AT_%(action_upper)s_%(header_upper)s: {
		action = cofaction_%(action)s_%(header)s(OFP12_VERSION, (uint%(length)s_t)(of1x_action->field.u%(length)s & OF1X_%(masking)s_MASK));
	} break;
"""

MAP_REVERSE_PACKET_MATCH_SKELETON = """
	if(packet_matches->%(header)s_%(field)s)
		match.insert(coxmatch_ofx_%(header)s_%(field)s(packet_matches->%(header)s_%(field)s));
"""

def generate_packet_classifier_h(fields):
    skeleton = read_template(TEMPLATES_DIR + "/packetclassifier.h.template") 
    
    skeleton_attrs = copy.copy(fields[0])
    header = fields[0]['header']
    skeleton_attrs['class'] = "\tclass f%sframe;\n" % header
    skeleton_attrs['header_access'] = "\tvirtual rofl::f%sframe* %s (int idx = 0) const=0;\n" % (header, header)
    
    skeleton_attrs['pop_operations'] = ""
    for field in fields:
        if field.get('action') == 'pop':
            skeleton_attrs['pop_operations'] += "\tvirtual void pop_%s(uint16_t ether_type)=0;\n" % header
    
    skeleton_attrs['push_operations'] = ""
    for field in fields:
        if field.get('action')== 'push':
            skeleton_attrs['push_operations'] += "\tvirtual rofl::f%sframe* push_%s(uint16_t ether_type)=0;\n" % (header, header)
        
    return skeleton % skeleton_attrs
    
def generate_static_pktclassifier_h(fields):
    skeleton = read_template(TEMPLATES_DIR + "/static_pktclassifier.h.template") 
    
    skeleton_attrs = copy.copy(fields[0])
    header = fields[0]['header']
    skeleton_attrs['headers'] = "#include <rofl/common/protocols/f%sframe.h>\n" % header
    skeleton_attrs['header_access'] = "\tvirtual rofl::f%sframe* %s (int idx = 0) const;\n" % (header, header)
    
    skeleton_attrs['pop_operations'] = ""
    for field in fields:
        if field.get('action') == 'pop':
            skeleton_attrs['pop_operations'] += "\tvirtual void pop_%s(uint16_t ether_type);\n" % header
    
    skeleton_attrs['push_operations'] = ""
    for field in fields:
        if field.get('action') == 'push':
            skeleton_attrs['push_operations'] += "\tvirtual rofl::f%sframe* push_%s(uint16_t ether_type);\n" % (header, header)
   
    skeleton_attrs['header_type'] = "\t\tHEADER_TYPE_%s,\n" % header.upper()
    skeleton_attrs['max_occurances'] = "\tstatic const unsigned int MAX_%s_FRAMES = 1;\n" % header.upper()
    skeleton_attrs['max_occurances_values'] = "\t\t\t\t\t\t\tMAX_%s_FRAMES +\n" % header.upper()
    skeleton_attrs['relative_positions'] = "static const unsigned int FIRST_%s_FRAME_POS = FIRST_GTP_FRAME_POS+MAX_GTP_FRAMES;\n" % header.upper()
    skeleton_attrs['header_parse'] = "void parse_%s(uint8_t *data, size_t datalen);\n" % header
    
    return skeleton % skeleton_attrs
    
def generate_static_pktclassifier_c(fields):
    skeleton = read_template(TEMPLATES_DIR + "/static_pktclassifier.c.template") 
    
    skeleton_attrs = copy.copy(fields[0])
    header = fields[0]['header']
    
    skeleton_attrs['initializers'] = INIT_SKELETON % skeleton_attrs
    skeleton_attrs['getters'] = GETTER_SKELETON % skeleton_attrs
    skeleton_attrs['parsers'] = PARSER_SKELETON % skeleton_attrs
    
    skeleton_attrs['pop_operations'] = ""
    for field in fields:
        if field.get('action') == 'pop':
            skeleton_attrs['pop_operations'] += "\tvirtual void pop_%s(uint16_t ether_type);\n" % header
    
    skeleton_attrs['push_operations'] = ""
    for field in fields:
        if field.get('action') == 'push':
            skeleton_attrs['push_operations'] += "\tvirtual rofl::f%sframe* push_%s(uint16_t ether_type);\n" % (header, header)
   
    skeleton_attrs['header_type'] = "\t\tHEADER_TYPE_%s,\n" % header.upper()
    skeleton_attrs['max_occurances'] = "\tstatic const unsigned int MAX_%s_FRAMES = 1;\n" % header.upper()
    skeleton_attrs['max_occurances_values'] = "\t\t\t\t\t\t\tMAX_%s_FRAMES +\n" % header.upper()
    skeleton_attrs['relative_positions'] = "static const unsigned int FIRST_%s_FRAME_POS = FIRST_GTP_FRAME_POS+MAX_GTP_FRAMES;\n" % header.upper()
    skeleton_attrs['header_parse'] = "void parse_%s(uint8_t *data, size_t datalen);\n" % header
    skeleton_attrs['pop_operations_body'] =  POP_SKELETON % skeleton_attrs
    skeleton_attrs['push_operations_body'] =  PUSH_SKELETON % skeleton_attrs
    skeleton_attrs['ether_parse'] = ETHER_PARSE_SKELETON % skeleton_attrs
    
    return skeleton % skeleton_attrs
    
def generate_packet_c(fields):
    skeleton = read_template(TEMPLATES_DIR + "/packet.c.template") 
    skeleton_attrs = copy.copy(fields[0])
    header = fields[0]['header']
    
    code1 = "#include <rofl/common/protocols/f%sframe.h>" % header
    
    code2 = ""
    for field in fields:
        if 'field' in field:
            code2 += GET_SKELETON % field
            code2 += SET_SKELETON % field
        if field.get('action') == 'push':
            code2 += PUSH2_SKELETON % field
        if field.get('action') == 'pop':
            code2 += POP2_SKELETON % field
    
    return skeleton % (code1, code2)
    
def generate_translation_utils_c(fields):
    skeleton = read_template(TEMPLATES_DIR + "/of12_translation_utils.c.template")
    
    header = fields[0]['header']
    
    code0 = EXPERIMENTAL_INCLUDES_SKELETON % (header, header)
    
    code1 = ""
    for field in fields:
        if 'field' in field:
            code1 += MATCH_TRANSLATION_SKELETON % field
    
    code2    = ""
    for field in fields:
        if 'field' in field:
            code2 += MATCH_SET_SKELETON % field 
    
    code3 = ""
    for field in fields:        
        if field.get('action') in ('push', 'pop'):
            code3 += ACTION_SET_SKELETON % field
            
    code4 = ""
    for field in fields:
        if 'field' in field:
            code4 += REVERSE_MATCH_SKELETON % field         

    code5 = ""
    for field in fields:
        if field.get('action') in ('push', 'pop'):
            code5 += REVERSE_ACTION_SKELETON % field   
    
    code6 = ""
    for field in fields:
        if 'field' in field:
            code6+= MAP_REVERSE_PACKET_MATCH_SKELETON % field               

    return skeleton % (code0, code1, code2, code3, code4, code5, code6)

def generate_xdpd(fields):
    add_fields_properties(fields)
    header = fields[0]['header']
    
    location = XDPD_GNU_LINUX_DIR + '/io/packet_classifiers/'
    generate_file(location + 'packetclassifier.h', generate_packet_classifier_h(fields))
    generate_file(location + 'static_pktclassifier.h', generate_static_pktclassifier_h(fields))
    generate_file(location + 'static_pktclassifier.cc', generate_static_pktclassifier_c(fields))
    
    location = XDPD_GNU_LINUX_DIR + '/pipeline-imp/'
    generate_file(location + 'packet.cc', generate_packet_c(fields))
    
    location = XDPD_OPENFLOW + '/openflow12/'
    generate_file(location + 'of12_translation_utils.cc', generate_translation_utils_c(fields))

if __name__ == "__main__":
    generate_xdpd([{'header': 'pad_tag', 'action':'pop', 'length': '32'}, 
                            {'header': 'pad_tag', 'action':'push', 'length': '32'}, 
                            {'header': 'pad_tag', 'field':'a', 'length':'8', 'action':'set'},
                            {'header': 'pad_tag', 'field':'b', 'length':'16', 'action':'set'}])
