from config import ROFL_DIR, TEMPLATES_DIR
from pad_utils import read_template, generate_file, add_fields_properties


ROFL_EXPERIMENTAL_ACTIONS_MAKEFILE_SKELETON = """
MAINTAINERCLEANFILES = Makefile.in

noinst_LTLIBRARIES = libopenflow_experimental_actions.la
libopenflow_experimental_actions_la_SOURCES = gtp_actions.h gtp_actions.cc pppoe_actions.h pppoe_actions.cc %s

library_includedir=$(includedir)/rofl/common/openflow/experimental/actions
library_include_HEADERS = gtp_actions.h pppoe_actions.h %s
"""
    
def generate_openflow_pipeline_action_h(fields):
    skeleton = read_template(TEMPLATES_DIR + "/of1x_action.h.template")
        
    code1 = ""
    for field in fields:
        if 'field' not in field:
            code1 += "\tOF1X_AT_%(action_upper)s_%(header_upper)s,\n" % field
        else:
            code1 += "\tOF1X_AT_%(action_upper)s_FIELD_%(header_upper)s_%(field_upper)s,\n" % field
    
    code2 = ""
    for field in fields:
        if 'field' not in field:
            code2 += "\tOF12PAT_%(action_upper)s_%(header_upper)s,\n" % field
            
    return skeleton % (code1, code2)
 
def generate_openflow_pipeline_action_c(fields):
    skeleton = read_template(TEMPLATES_DIR + "/of1x_action.c.template")  
    
    code1 = ""
    for field in fields:
        if 'field' not in field:
            code1 += "\t\tcase OF1X_AT_%(action_upper)s_%(header_upper)s:\n" % field
        else:
            code1 += "\t\tcase OF1X_AT_%(action_upper)s_FIELD_%(header_upper)s_%(field_upper)s:\n" % field
            
        code1 += "\t\t\taction->field.u%(length)s = field.u%(length)s&OF1X_%(masking)s_MASK;\n" % field
        code1 += "\t\t\taction->ver_req.min_ver = OF_VERSION_12;\n"
        code1 += "\t\t\tbreak;\n"
    
    code2 = ""
    for field in fields:
        if 'field' not in field:
            code2 += "\t\tcase OF1X_AT_%(action_upper)s_%(header_upper)s:\n" % field
            code2 += "\t\t\tplatform_packet_%(action)s_%(header)s(pkt, action->field.u%(length)s);\n" % field
            code2 += "\t\t\tpkt_matches->eth_type= platform_packet_get_eth_type(pkt);\n" % field
            code2 += "\t\t\tpkt_matches->pkt_size_bytes = platform_packet_get_size_bytes(pkt);\n" % field
        else:
            code2 += "\t\tcase OF1X_AT_%(action_upper)s_FIELD_%(header_upper)s_%(field_upper)s:\n" % field
            code2 += "\t\t\tplatform_packet_set_%(header)s_%(field)s(pkt, action->field.u%(length)s);\n" % field
            code2 += "\t\t\tpkt_matches->%(header)s_%(field)s = action->field.u%(length)s;\n" % field
        code2 += "\t\t\tbreak;\n"      
        
    code3 = ""
    for field in fields:
        if 'field' not in field:
            code3 += """\t\tcase OF1X_AT_%(action_upper)s_%(header_upper)s: ROFL_PIPELINE_DEBUG_NO_PREFIX("%(action_upper)s_%(header_upper)s"); \n""" % field
        else:
            code3 += """\t\tcase OF1X_AT_%(action_upper)s_FIELD_%(header_upper)s_%(field_upper)s: \n""" % field
            code3 += """\t\t\tROFL_PIPELINE_DEBUG_NO_PREFIX("%(action_upper)s_%(header_upper)s_%(field_upper)s: 0x%%x",action.field.u%(length)s); \n""" % field
        code3 += "\t\t\tbreak;\n"    

    return skeleton % (code1, code2, code3)
    
def generate_experimental_action_h(fields):
    skeleton = read_template(TEMPLATES_DIR + "/rofl_experimental_actions.h.template") 
    fields[0]['experimental_id'] = 3
    return skeleton % fields[0]
    
def generate_experimental_action_c(fields):
    skeleton = read_template(TEMPLATES_DIR + "/rofl_experimental_actions.c.template") 
    return skeleton % fields[0]

def generate_experimental_makefile(fields):
    header = fields[0]['header']
    code1 = "%s_actions.h %s_actions.cc" % (header, header)
    code2 = "%s_actions.h" % header
    return ROFL_EXPERIMENTAL_ACTIONS_MAKEFILE_SKELETON % (code1, code2)
    

def generate_datapath_pipeline_platform_actions_h(fields):
    skeleton = read_template(TEMPLATES_DIR + "/packet_actions.h.template")  
    
    code = ""
    for field in fields:
        if 'field' not in field:
            code += "void platform_packet_%(action)s_%(header)s(datapacket_t* pkt, uint16_t ether_type);\n" % field # TODO
    return skeleton % code

    
def generate_rofl_actions(fields):
    add_fields_properties(fields)
    header = fields[0]['header']
    
    location = ROFL_DIR + '/datapath/pipeline/openflow/openflow1x/pipeline/'
    generate_file(location + 'of1x_action.h', generate_openflow_pipeline_action_h(fields))
    generate_file(location + 'of1x_action.c', generate_openflow_pipeline_action_c(fields))
    
    location = ROFL_DIR + '/common/openflow/experimental/actions/'
    generate_file(location + '%s_actions.h' % header, generate_experimental_action_h(fields))
    generate_file(location + '%s_actions.cc' % header, generate_experimental_action_c(fields))
    generate_file(location + 'Makefile.am', generate_experimental_makefile(fields))
    
    generate_file(ROFL_DIR + '/datapath/pipeline/platform/packet_actions_autogenerated.h', generate_datapath_pipeline_platform_actions_h(fields))
    
    experimental_ids = {}
    for field in fields:
        if 'field' in field:
            continue
        if 'experimental_id' in field:
            if field['header'] not in experimental_ids:
                experimental_ids[field['header']] = []
            full_action_name = "%s_%s" % (field['action'], field['header'])
            experimental_ids[field['header']].append({'action':full_action_name, 'experimental_id':field['experimental_id']})
        else:
            experimental_ids[field['header']].append({'action':full_action_name, 'experimental_id':4}) # TODO FIX
    return experimental_ids


if __name__ == "__main__":
    generate_rofl_actions([{'header': 'pad_tag', 'action':'pop', 'length': '32'}, 
                               {'header': 'pad_tag', 'action':'push', 'length': '32'}, 
                               {'header': 'pad_tag', 'field':'a', 'length':'8', 'action':'set'},
                               {'header': 'pad_tag', 'field':'b', 'length':'16', 'action':'set'}])