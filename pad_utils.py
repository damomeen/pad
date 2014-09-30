def read_template(filename):
    return file(filename, 'r').read()
    
def generate_file(filename, content):
    f = file(filename, 'w')
    f.write(content)
    f.close()
    print "   File generated: %s" % filename
    
def add_field_properties(field):
    field['header_upper'] = field['header'].upper()
    if 'field' in field:
        field['field_upper'] = field['field'].upper()
    if 'action' in field:
        field['action_upper'] = field['action'].upper()
    
    if int(field['length']) % 8 !=0:
        field['masking'] = '%s_BITS' % field['length']
    else:
        field['masking'] = '%d_BYTE' % (int(field['length'])/8,)
        
    if field['length'] == '8':
        field['container'] = 'byte'
    elif field['length'] == '16':
        field['container'] = 'word'
    elif field['length'] == '32':
        field['container'] = 'dword'
    #field['lower_protocol'] = '' # TODO
    if 'lower_protocol_field' in field:
        field['lower_protocol_field_upper'] = field['lower_protocol_field'].upper() # TODO
        
def add_fields_properties(fields):
    for field in fields:
        add_field_properties(field)
        
def approve_fields_with_attribute(fields, attribute):
    return [field for field in fields if attribute in field]