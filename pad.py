from xdpd_gnu_linux_v03_gen.generate_rofl_xdpd import translate_p4_to_xdpd, generate_xdpd_rofl
from p4_interpreter import parse_p4



__protocols = {}
__functions = {}

# ---------------- PAD API functions ---------------------------------------------------

# --- CAPABILITIES ---

def get_all_capabilities():
    raise Exception("Not implemented")
    
def get_capability(name):
    raise Exception("Not implemented")
    
    
#  --- PROTOCOLS --- 

def add_protocol(name, spec):
    __protocols[name] = spec

def remove_protocol(name):
    if name in __protocols:
        del __protocols[name]

def remove_all_protocols():
    global __protocols
    __protocols = {}


#  --- FUNCTIONS --- 

def add_function(name, spec):
     __functions[name] = spec

def remove_function(name):
    if name in __functions:
        del __functions[name]
    
def remove_all_functions():
    global __functions
    __functions = {}
    
 
#  --- COMMIT --- 

def commit_configuration():
    
    def join_specs(spec_dict_container):
        "returns all specs in a single string"
        joined_specs = ""
        for spec in spec_dict_container.values():
            joined_specs += spec
        return joined_specs

    fields = translate_p4_to_xdpd(parse_p4(join_specs(__protocols)),
                                             parse_p4(join_specs(__functions)))
    result = generate_xdpd_rofl(fields)
    
    # TODO automatic ROFL and XDPD recompilation
    return result
    
 
#  --- ENTRIES --- 

def add_entry(structure_id, key, mask, result):
    raise NotImplementedError()
    
def remove_entry(structure_id, key, mask):
    raise NotImplementedError()
    
def remove_all_entries(structure_id):
    raise NotImplementedError()

    
    
if __name__ == "__main__":
    
    import pprint
    
    # Example of usage:
    
    ethernet_hrd = """
            header ethernet {
                fields {
                    dst_addr : 48;
                    src_addr : 48;
                    ethertype : 16;
                }
            }
            parser start {
                ethernet;
              }
              parser ethernet {
                switch(ethertype) { 
                  case 0x9100: ictp;
                }
              }
    """
    ictp_hdr = """
            header ictp {   
                fields {
                  nid : 32; 
                  csn : 32;   
                }
              }
    """
    push_ictp = """
            action push_ictp {
                add_header(ictp, sizeof(ethernet));
            }
    """
    pop_ictp = """
            action pop_ictp {
                remove_header(ictp, sizeof(ethernet));
            }
    """
    add_protocol("Ethernet", ethernet_hrd)
    add_protocol("ICTP", ictp_hdr)
    add_function("push_ictp", push_ictp)
    add_function("pop_ictp", pop_ictp)   
    
    of_extensions_ids = commit_configuration()
    pprint.pprint(of_extensions_ids)

    
