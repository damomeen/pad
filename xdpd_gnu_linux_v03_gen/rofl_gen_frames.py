from config import ROFL_DIR, TEMPLATES_DIR
from pad_utils import read_template, generate_file, add_fields_properties, approve_fields_with_attribute
import copy

FIELD_GETTER = """
uint%(length)s_t f%(header)sframe::get_%(field)s()
{
    return be%(length)stoh(%(header)s_hdr->%(field)s);
}
"""
FIELD_SETTER = """
void f%(header)sframe::set_%(field)s(uint%(length)s_t %(field)s)
{
    %(header)s_hdr->%(field)s = htobe%(length)s(%(field)s);
}
"""

def generate_common_protocol_frame_h(fields):
    skeleton = read_template(TEMPLATES_DIR + "/frame.h.template") 
    
    skeleton_attrs = copy.copy(fields[0])
    
    skeleton_attrs['fields'] = ""
    for field in fields:
        skeleton_attrs['fields'] += "\t\tuint%(length)s_t %(field)s;\n" % field
        
    skeleton_attrs['fields_getters'] = ""
    for field in fields:
        skeleton_attrs['fields_getters'] += "\tuint%(length)s_t get_%(field)s();\n" % field
    
    skeleton_attrs['fields_setters'] = ""
    for field in fields:
        skeleton_attrs['fields_setters'] += "\tvoid set_%(field)s(uint%(length)s_t %(field)s);\n" % field
        
    return skeleton % skeleton_attrs
    
def generate_common_protocol_frame_c(fields):
    skeleton = read_template(TEMPLATES_DIR + "/frame.c.template") 
    
    skeleton_attrs = copy.copy(fields[0])
    
    skeleton_attrs['field_printed_list'] = ""
    for field in fields:
        skeleton_attrs['field_printed_list'] += "%(field)s[%%d] " % field
        
    skeleton_attrs['fields_to_be_printed'] = ""
    for field in fields:
        skeleton_attrs['fields_to_be_printed'] += "\t\t\tbe%(length)stoh(%(header)s_hdr->%(field)s),\n" % field

    skeleton_attrs['fields_getters'] = ""
    for field in fields:
        skeleton_attrs['fields_getters'] += FIELD_GETTER % field
        
    skeleton_attrs['fields_setters'] = ""
    for field in fields:
        skeleton_attrs['fields_setters'] +=  FIELD_SETTER % field
        
    return skeleton % skeleton_attrs
    
def generate_common_protocol_makefile(fields):
    skeleton = read_template(TEMPLATES_DIR + "/protocols_makefile.am.template") 
    
    header = fields[0]['header']
    
    return skeleton % ("f%sframe.cc " % header, "f%sframe.h " % header)
    
def generate_rofl_frames(fields):
    fields = approve_fields_with_attribute(fields, 'field')
    add_fields_properties(fields)
    header = fields[0]['header']
    
    location = ROFL_DIR + '/common/protocols/'
    generate_file(location + 'f%sframe.h' % header, generate_common_protocol_frame_h(fields))
    generate_file(location + 'f%sframe.cc' % header, generate_common_protocol_frame_c(fields))
    generate_file(location + 'Makefile.am', generate_common_protocol_makefile(fields))
    
if __name__ == "__main__":
    generate_rofl_frames([{'header': 'pad_tag', 'field':'a', 'length':'8', 'lower_protocol_field':'ip_proto', 'lower_protocol_field_value': 0x700},
                               {'header': 'pad_tag', 'field':'b', 'length':'16'}])



