from rofl_gen_experimental_actions import generate_rofl_actions
from rofl_gen_experimental_matches import generate_rofl_matches
from rofl_gen_frames import generate_rofl_frames
from xdpd_gen import generate_xdpd

header = {'name':'ictp',
              'lower_protocol_field':'eth_type',
              'lower_protocol_field_value': 0x9100,
              'actions':  [ {'action':'pop', 'length': '32'}, 
                                  {'action':'push', 'length': '32'}, 
               ],
              'fields':  [ {'field':'nid', 'length':'32'},
                                {'field':'csn', 'length':'32'}, 
               ], 
}


def desc_flattening(header):
    fields = header['actions']
    
    for field in header['fields']:
        field['action'] = 'set'
        fields.append(field)
        
    for field in fields:
        field['header'] = header['name']
        field['lower_protocol_field'] = header['lower_protocol_field']
        field['lower_protocol_field_value'] = header['lower_protocol_field_value']
    
    return fields

fields = desc_flattening(header)

if __name__ == "__main__":
    generate_rofl_actions(fields)
    generate_rofl_matches(fields)
    generate_rofl_frames(fields)
    generate_xdpd(fields)