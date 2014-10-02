from pyparsing import Literal, Keyword, Word, Group, Combine, Dict
from pyparsing import OneOrMore, ZeroOrMore, Optional, nums, alphas
import unittest

# ------------- COMMON LITERALS and WORDS --------------------------------------------------------------------------

LBRACK = Literal("{").suppress()
RBRACK = Literal("}").suppress()
LPARENTHES = Literal("(").suppress()
RPARENTHES = Literal(")").suppress()
EQUALS = Literal(":").suppress()
SEMI   = Literal(";").suppress()
COMMA   = Literal(",").suppress()

FIELD = Word(alphas + '_')
FIELD_LEN = Word(nums)
PROTOCOL = Word(alphas + '_' + nums)
VALUE = Word(nums)
ACTION = Word(alphas + '_' + nums)

# ------------- UTILITY FUNCTIONS -------------------------------------------------------------------------------------
    
def fields2dict(s, l, t):
    d = {'fields':dict()}
    for field in t[0][1:]:
        field, len = field
        d['fields'][field] = len
    return d
    
def header2dict(s, l, t):
    d, header_type, fields = dict(), t[0][1], t[0][2]
    d['header'] = header_type
    d.update(fields)
    return d
    
def start2dict(s, l, t):
    return {t[0][1]: t[0][2]}
    
def parser2dict(s, l, t):
    return start2dict(s, l, t)

def case2dict(s, l, t):
    return start2dict(s, l, t)
    
def switch2dict(s, l, t):
    cases = dict()
    for v in t[0][2:]:
        cases.update(v)
    return {t[0][1]: cases}
    
def parsers2dict(s, l, t):
    parsers = dict()
    for v in t[0]:
        parsers.update(v)
    return parsers
    
def sizeof2dict(s, l, t):
    return {t[0][0]: t[0][1]}
    
def addheader2dict(s, l, t):
    return {"function": t[0][0], "header":t[0][1], "offset":t[0][2]}
    
def remheader2dict(s, l, t):
    return addheader2dict(s, l, t)
    
def instruction2list(s, l, t):
    return t[0]
    
def action2dict(s, l, t):  
    return {t[0][1]: t[0][2:]}
    
    
# ------------- PARSE FUNCTIONS  -------------------------------------------------------------------------------------

def parse_headers(headers):
    field_info = Group(FIELD + EQUALS + FIELD_LEN + SEMI)
    fields = Group(Keyword("fields") + LBRACK + OneOrMore(field_info) + RBRACK).setParseAction(fields2dict)
    header =  Group(Keyword("header") + PROTOCOL +  LBRACK + fields + RBRACK).setParseAction(header2dict)
    all_headers = ZeroOrMore(header)
    return all_headers.parseString(headers)
  
        
def parse_parsers(parsers):
    field_value = Combine(Optional("0x") + VALUE)
    case = Group(Keyword("case") + field_value + EQUALS + PROTOCOL + SEMI).setParseAction(case2dict)
    cases = OneOrMore(case)
    switch = Group(Keyword("switch") + LPARENTHES + FIELD + RPARENTHES + LBRACK + cases + RBRACK).setParseAction(switch2dict)
    parser = Group(Keyword("parser") + PROTOCOL + LBRACK + switch + RBRACK).setParseAction(parser2dict)
    starter = Group(Keyword("parser") + Keyword("start") + LBRACK + PROTOCOL + SEMI + RBRACK).setParseAction(start2dict)
    all_parsers = Group(starter & OneOrMore(parser)).setParseAction(parsers2dict)
    return all_parsers.parseString(parsers)[0]
   
          
def parse_actions(actions):
    sizeof = Group(Keyword("sizeof") + LPARENTHES + PROTOCOL + RPARENTHES).setParseAction(sizeof2dict)
    offset = sizeof                 # other possibilities to be addded later
    add_header_func = Group(Keyword("add_header") + LPARENTHES + PROTOCOL + COMMA + offset + RPARENTHES + SEMI).setParseAction(addheader2dict)
    rem_header_func = Group(Keyword("remove_header") + LPARENTHES + PROTOCOL + COMMA + offset + RPARENTHES + SEMI).setParseAction(remheader2dict)
    basic_instruction = Group(add_header_func | rem_header_func).setParseAction(instruction2list)
    basic_instructions = OneOrMore(basic_instruction)
    action = Group(Keyword("action") + ACTION + LBRACK + basic_instructions + RBRACK).setParseAction(action2dict)
    all_actions = ZeroOrMore(action)
    return all_actions.parseString(actions)
    
 
# ------------- TESTING  -------------------------------------------------------------------------------------        

class TestParseHeaders(unittest.TestCase):
    def setUp(self):
        self.text = """
            header ethernet {
                fields {
                    dst_addr : 48;
                    src_addr : 48;
                    ethertype : 16;
                }
            }
             header ictp {   
                fields {
                  nid : 32; 
                  csn : 32;   
                }
              }
        """
        self.result =str([{'header': 'ethernet', 
                                'fields': {'ethertype': '16', 'src_addr': '48', 'dst_addr': '48'}
                              }, 
                              {'header': 'ictp', 
                                'fields': {'csn': '32', 'nid': '32'}
                              }
                            ])

    def test(self):
        self.assertEqual(str(parse_headers(self.text)), self.result)

class TestParseParsers(unittest.TestCase):
    def setUp(self):
        self.text = """
            parser start {
                ethernet;
              }
              parser ethernet {
                switch(ethertype) { 
                  case 0x9100: ictp;
                  case 0x800: ipv4;
                }
              }
        """
        self.result =str({'start': 'ethernet', 
                                'ethernet': {'ethertype': {'0x9100': 'ictp', '0x800': 'ipv4'}}
                            })

    def test(self):
        self.assertEqual(str(parse_parsers(self.text)), self.result)
        
class TestParseActions(unittest.TestCase):
    def setUp(self):
        self.text = """
            action push_ictp {
                add_header(ictp, sizeof(ethernet));
            }
            action pop_ictp {
                remove_header(ictp, sizeof(ethernet));
            }
            action nothing_ictp {
                add_header(ictp, sizeof(ethernet));
                remove_header(ictp, sizeof(ethernet));
            }
        """
        self.result =str([{'push_ictp': 
                                    [{'function': 'add_header', 
                                       'header': 'ictp', 
                                       'offset': {'sizeof': 'ethernet'}
                                    }]
                               },
                               {'pop_ictp':
                                   [{'function': 'remove_header', 
                                      'header': 'ictp', 
                                      'offset': {'sizeof': 'ethernet'}
                                   }]
                                },
                                {'nothing_ictp':
                                    [{'function': 'add_header', 
                                       'header': 'ictp', 
                                       'offset': {'sizeof': 'ethernet'}
                                      }, 
                                      {'function': 'remove_header', 
                                        'header': 'ictp', 
                                        'offset': {'sizeof': 'ethernet'}
                                      }]
                                }
                            ])

    def test(self):
        self.assertEqual(str(parse_actions(self.text)), self.result)
        
{'name':'ictp',
              'lower_protocol_field':'eth_type',
              'lower_protocol_field_value': 0x9100,
              'actions':  [ {'action':'pop', 'length': '32'}, 
                                  {'action':'push', 'length': '32'}, 
               ],
              'fields':  [ {'field':'nid', 'length':'32'},
                                {'field':'csn', 'length':'32'}, 
               ], 
}

if __name__ == "__main__":
    unittest.main()