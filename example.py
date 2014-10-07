import pprint
import pad
    
def upload_ictp_v1():
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
    pad.add_protocol("Ethernet", ethernet_hrd)
    pad.add_protocol("ICTP", ictp_hdr)
    pad.add_function("push_ictp", push_ictp)
    pad.add_function("pop_ictp", pop_ictp)   
    
    of_extensions_ids = pad.commit_configuration()
    pprint.pprint(of_extensions_ids)
    
    
def remove_ictp_v1():
    pad.remove_protocol("ICTP")


def upload_ictp_v2():
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
                  version : 8;
                  slice : 16;
                  __skip__ : 8;
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
    pad.add_protocol("Ethernet", ethernet_hrd)
    pad.add_protocol("ICTP", ictp_hdr)
    pad.add_function("push_ictp", push_ictp)
    pad.add_function("pop_ictp", pop_ictp)   
    
    of_extensions_ids = pad.commit_configuration()
    pprint.pprint(of_extensions_ids)   



if __name__ == "__main__":
    #upload_ictp_v1()
    #remove_ictp_v1()
    upload_ictp_v2()