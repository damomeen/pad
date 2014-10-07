What it is
=======

Programmable Abstraction of Datapath (PAD) which will help you build new data plane protocols headers and actions into OpenFlow GNU-Linux software switch based on xDPd/ROFL software. A new data plane protocols are specified using P4 language [1].

[1] Programming Protocol-Independent Packet Processors, http://arxiv.org/abs/1312.1719

Limitations
========

It is PAD v0.1 for xDPd/ROFL and thus:

 - OpenFlow v1.2 is only supported (OF match and action extensions are used for manipulation of new headers)
 - Currently you can add a new header just after Ethernet header
 - A new header can be composed of any amount of 1-, 2- and 4- bytes fields
 - Only header add/remove actions are provided (support for P4 specification of actions declarations is currently very weak)

Requirements
==========

- ROFL libraries installed [2]
- xDPd libraries installed [3]
- Python v2.7

[2] http://www.roflibs.org/, https://github.com/bisdn/rofl-core

[3] http://www.xdpd.org/, https://github.com/bisdn/xdpd

How to configure 
=============

Download ROFL, xDPd and PAD projects:

    git clone https://github.com/bisdn/rofl-core.git
    git clone https://github.com/bisdn/xdpd.git
    git clone https://github.com/damomeen/pad
    
Currently PAD support only master-0.3 branch of both xDPd and ROFL thus you must switch to that branches:
   
    cd rofl-core
    git checkout master-0.3
    cd ../xdpd
    git checkout master-0.3

Edit xDPd/ROFL generator config file and provide current locations of ROFL and xDPd projects:

    cd ../pad/xdpd_gnu_linux_v03_gen
    nano config.py 

Before futher configuration of ROFL and xDPd, firstly, it is required to generate example extension for ROFL and xDPd project (it will allow for correct configuration of ROFL and xDPd): 

    cd ../
    python pad.py

Continue configuration of both ROFL and xDPd accordingly their manuals:

    cd ../rofl-core
    ./autogen.sh
    cd build
    ../configure
    
    cd ../../xdpd
    ./autogen.sh
    cd build
    ../configure

Right now you are able to import pad library into your own program and generate your own extensions in xDPd and ROFL.

Usage
====

    ###### your_module.py #####
    
    import pad
    
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


Authorship
========
(c) Copyright PSNC 2014
Damian Parniewicz<damian.parniewicz (at) gmail.com>

Funded by EU ICT ALIEN project, http://www.fp7-alien.eu/
