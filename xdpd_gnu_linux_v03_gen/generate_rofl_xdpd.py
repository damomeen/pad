from rofl_gen_experimental_actions import generate_rofl_actions
from rofl_gen_experimental_matches import generate_rofl_matches
from rofl_gen_frames import generate_rofl_frames
from xdpd_gen import generate_xdpd

from utils import generate_file, read_template
from config import ROFL_DIR, MODIFIED_DIR

import copy


def __desc_flattening(header):
    fields = header['actions']
    
    for field in header['fields']:
        field['action'] = 'set'
        fields.append(field)
        
    for field in fields:
        field['header'] = header['header']
        field['lower_protocol_field'] = header['lower_protocol_field']
        field['lower_protocol_field_value'] = header['lower_protocol_field_value']
    
    return fields
    
def translate_p4_to_xdpd(p4_protocols, p4_actions):
    for  _protocol in p4_protocols['headers']:
        if _protocol['header'] == 'ethernet':
            continue
        else:
            protocol = copy.deepcopy(_protocol)
            break       # only one protocol for time being
            
    if protocol == None:
        raise Exception("Missing additional protocol description (besides Ethernet)")
        
    for parser in p4_protocols['parsers']:
        if parser[0] == "ethernet":
            protocol['lower_protocol_field'] = 'eth_type' # FIXED
            for case in parser[2]:
                if case == protocol['header']:
                    protocol['lower_protocol_field_value'] = parser[2][case]
                    
    protocol['actions'] = []
    for action in p4_actions['actions']:
        if action[1]['header'] == protocol['header']:
            _action = {}
            _action['action'] = action[0].replace(protocol['header'], "").replace("_", "")
            _action.update(action[1])
            _action['length'] = '32'
            protocol['actions'].append(_action)

    return protocol
    
def __copy_modified_files():
    generate_file(ROFL_DIR + "/common/endianess_other.h", read_template(MODIFIED_DIR + "/endianess_other.h"))
    generate_file(ROFL_DIR + "/common/Makefile.am", read_template(MODIFIED_DIR + "/rofl_common_Makefile.am"))
    generate_file(ROFL_DIR + "/datapath/pipeline/openflow/openflow1x/pipeline/Makefile.am", read_template(MODIFIED_DIR + "/rofl_datapath_pipeline_Makefile.am"))

def generate_xdpd_rofl(fields):
    
    __copy_modified_files()
    
    fields = __desc_flattening(fields)
    actions_experimental_ids = generate_rofl_actions(fields)
    matches_experimental_ids = generate_rofl_matches(fields)
    generate_rofl_frames(fields)
    generate_xdpd(fields)
    
    for header in actions_experimental_ids:
        matches_experimental_ids[header] += actions_experimental_ids[header]
        
    return matches_experimental_ids
    
    



if __name__ == "__main__":
    protocol = {'header':'ictp',
              'lower_protocol_field':'eth_type',
              'lower_protocol_field_value': '0x9100',
              'actions':  [ {'action':'pop', 'length': '32'}, 
                                  {'action':'push', 'length': '32'}, 
               ],
              'fields':  [ {'field':'nid', 'length':'32'},
                                {'field':'csn', 'length':'32'}, 
               ], 
    }
    fields = __desc_flattening(protocol)
    generate_xdpd_rofl(fields)